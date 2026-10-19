//go:build race

package test

// isoRace thins the attack catalogue out under the race detector, which makes
// the full run several times slower; the unthinned run is the canonical one.
const isoRace = true
