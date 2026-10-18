{{- define "mtp.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "mtp.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}
{{- define "mtp.labels" -}}
app.kubernetes.io/name: {{ include "mtp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}
{{- define "mtp.selector" -}}
app.kubernetes.io/name: {{ include "mtp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "mtp.secretName" -}}{{ default (printf "%s-secrets" (include "mtp.fullname" .)) .Values.existingSecret }}{{- end -}}
{{- define "mtp.port" -}}{{ trimPrefix ":" (index (splitList ":" .) 1) }}{{- end -}}
