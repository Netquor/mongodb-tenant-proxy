package upstream

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/x/bsonx/bsoncore"
)

type awsCreds struct {
	AccessKeyID, SecretAccessKey, SessionToken string
}

// awsCredentials resolves credentials at dial time (so rotating environment
// credentials are picked up): explicit config, then username/password, then
// the environment, then the ECS container credentials endpoint.
func (d *Dialer) awsCredentials() (awsCreds, error) {
	c := awsCreds{d.cfg.AWSAccessKeyID, d.cfg.AWSSecretAccessKey, d.cfg.AWSSessionToken}
	if c.AccessKeyID == "" && d.cfg.Username != "" {
		c.AccessKeyID, c.SecretAccessKey = d.cfg.Username, d.cfg.Password
	}
	if c.AccessKeyID == "" {
		c = awsCreds{os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN")}
	}
	if c.AccessKeyID == "" {
		// The relative URI must be a plain path: anything else ("@host", "//host")
		// would repoint the fetch away from the fixed link-local ECS endpoint.
		if rel := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel != "" {
			if !strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "//") || strings.ContainsAny(rel, "@\\ \t\r\n") {
				return awsCreds{}, errors.New("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must be an absolute path")
			}
			return fetchECSCreds("http://169.254.170.2" + rel)
		}
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return c, errors.New("no AWS credentials (set upstream.awsAccessKeyId/awsSecretAccessKey, username/password, or AWS_* environment variables)")
	}
	return c, nil
}

func fetchECSCreds(url string) (awsCreds, error) {
	cl := http.Client{Timeout: 5 * time.Second}
	// #nosec G704 -- host is the fixed ECS link-local endpoint; the path was validated by the caller
	resp, err := cl.Get(url)
	if err != nil {
		return awsCreds{}, err
	}
	defer resp.Body.Close()
	var out struct{ AccessKeyId, SecretAccessKey, Token string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return awsCreds{}, err
	}
	return awsCreds{out.AccessKeyId, out.SecretAccessKey, out.Token}, nil
}

const stsBody = "Action=GetCallerIdentity&Version=2011-06-15"

// awsRegion derives the signing region from the STS host the server names.
func awsRegion(host string) string {
	if host == "sts.amazonaws.com" {
		return "us-east-1"
	}
	if p := strings.Split(host, "."); len(p) > 2 && p[1] != "" {
		return p[1]
	}
	return "us-east-1"
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// signAWS builds the SigV4 Authorization header for the STS
// GetCallerIdentity request MONGODB-AWS asks the server to replay.
func signAWS(c awsCreds, host string, serverNonce []byte, now time.Time) (authz, date string) {
	now = now.UTC()
	date = now.Format("20060102T150405Z")
	day := now.Format("20060102")
	region := awsRegion(host)
	nonce := base64.StdEncoding.EncodeToString(serverNonce)

	hdrs := []string{"content-length", "content-type", "host", "x-amz-date"}
	canon := fmt.Sprintf("content-length:%d\ncontent-type:application/x-www-form-urlencoded\nhost:%s\nx-amz-date:%s\n",
		len(stsBody), host, date)
	if c.SessionToken != "" {
		hdrs = append(hdrs, "x-amz-security-token")
		canon += "x-amz-security-token:" + c.SessionToken + "\n"
	}
	hdrs = append(hdrs, "x-mongodb-gs2-cb-flag", "x-mongodb-server-nonce")
	canon += "x-mongodb-gs2-cb-flag:n\nx-mongodb-server-nonce:" + nonce + "\n"
	signed := strings.Join(hdrs, ";")

	bodyHash := sha256.Sum256([]byte(stsBody))
	creq := "POST\n/\n\n" + canon + "\n" + signed + "\n" + hex.EncodeToString(bodyHash[:])
	creqHash := sha256.Sum256([]byte(creq))
	scope := day + "/" + region + "/sts/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(creqHash[:])

	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "sts")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	authz = fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", c.AccessKeyID, scope, signed, sig)
	return authz, date
}

// authAWS runs MONGODB-AWS: the server calls STS with the signed request we
// hand it and maps the resulting ARN to a MongoDB user.
func (d *Dialer) authAWS(c *Conn) error {
	creds, err := d.awsCredentials()
	if err != nil {
		return err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	first := bsoncore.BuildDocument(nil,
		bsoncore.AppendBinaryElement(nil, "r", 0, nonce),
		bsoncore.AppendInt32Element(nil, "p", 110),
	)
	resp, err := d.RunCommand(c, "$external", bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "saslStart", 1),
		bsoncore.AppendStringElement(nil, "mechanism", "MONGODB-AWS"),
		bsoncore.AppendBinaryElement(nil, "payload", 0, first),
	))
	if err != nil {
		return err
	}
	if err := replyErr(resp); err != nil {
		return err
	}
	_, payload, _ := resp.Lookup("payload").BinaryOK()
	sdoc := bsoncore.Document(payload)
	if err := sdoc.Validate(); err != nil {
		return fmt.Errorf("MONGODB-AWS: bad server payload: %w", err)
	}
	_, sn, _ := sdoc.Lookup("s").BinaryOK()
	host, _ := sdoc.Lookup("h").StringValueOK()
	if len(sn) != 64 || !bytes.Equal(sn[:32], nonce) {
		return errors.New("MONGODB-AWS: server nonce does not extend the client nonce")
	}
	if host == "" || len(host) > 255 || strings.Contains(host, "..") {
		return errors.New("MONGODB-AWS: invalid STS host from server")
	}
	authz, date := signAWS(creds, host, sn, time.Now())
	second := bsoncore.AppendStringElement(nil, "a", authz)
	second = bsoncore.AppendStringElement(second, "d", date)
	if creds.SessionToken != "" {
		second = bsoncore.AppendStringElement(second, "t", creds.SessionToken)
	}
	resp, err = d.RunCommand(c, "$external", bsoncore.BuildDocument(nil,
		bsoncore.AppendInt32Element(nil, "saslContinue", 1),
		valueElem("conversationId", resp.Lookup("conversationId")),
		bsoncore.AppendBinaryElement(nil, "payload", 0, bsoncore.BuildDocument(nil, second)),
	))
	if err != nil {
		return err
	}
	return replyErr(resp)
}
