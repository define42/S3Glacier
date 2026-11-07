// Package config loads the archive server's environment settings.
//
// Values remain strings: an environment variable, including an explicitly empty
// one, overrides its registered default. Callers interpret and validate values
// where they are used. Populate Settings before starting concurrent handlers;
// the registry does not synchronize updates.
package config

import (
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"os"
)

// SettingsType stores startup configuration values and their descriptions.
// Settings provides an initialized registry; mutations are not concurrent-safe.
type SettingsType struct {
	m map[string]SettingType
}

// SettingType records an unparsed setting value and its display description.
type SettingType struct {
	// Description is the text shown in the startup settings table.
	Description string
	// Value is the environment value or the registered default, without trimming.
	Value string
}

// Settings is the process-wide registry loaded by the server at startup.
var Settings = &SettingsType{m: make(map[string]SettingType)}

// Get returns a registered value, or an empty string for an unknown setting.
func (s *SettingsType) Get(id string) string {
	return s.m[id].Value
}

// Has reports whether a setting's current string is nonempty.
// It does not distinguish an unset variable from an explicitly empty value.
func (s *SettingsType) Has(id string) bool {
	return len(s.m[id].Value) > 0
}

// Set registers a setting, choosing the environment value when id is present.
// An explicitly empty environment value overrides defaultValue; neither value
// is trimmed or validated.
func (s *SettingsType) Set(id string, description string, defaultValue string) {
	if value, ok := os.LookupEnv(id); ok {
		s.m[id] = SettingType{Description: description, Value: value}
	} else {
		s.m[id] = SettingType{Description: description, Value: defaultValue}
	}
}

const (
	// ACME_SERVER names the ACME directory URL setting; empty disables ACME.
	ACME_SERVER = "ACME_SERVER"
	// SERVER_DOMAIN names the single hostname used for ACME certificate management.
	SERVER_DOMAIN = "SERVER_DOMAIN"
	// DISK_USAGE_ALLOWED names the shared filesystem usage threshold setting.
	DISK_USAGE_ALLOWED = "DISK_USAGE_ALLOWED"
	// EXTEND_LIFE_SUPPORT names the opt-in UUIDv4 month-offset interpretation setting.
	EXTEND_LIFE_SUPPORT = "EXTEND_LIFE_SUPPORT"
	// DATA_FOLDER names the root containing bucket definitions and archives.
	DATA_FOLDER = "DATA_FOLDER"
	// SERVER_PORT names the plain HTTP port setting; it does not control ACME ports.
	SERVER_PORT = "SERVER_PORT"
	// READ_TOKEN names the single literal token for HTTP read operations.
	READ_TOKEN = "READ_TOKEN"
	// WRITE_TOKEN names the single literal token for HTTP write operations.
	WRITE_TOKEN = "WRITE_TOKEN"
	// S3_READ_ONLY_USERS names the semicolon-separated S3 read-only credential list.
	S3_READ_ONLY_USERS = "S3_READ_ONLY_USERS"
	// S3_READ_WRITE_USERS names the semicolon-separated S3 read/write credential list.
	S3_READ_WRITE_USERS = "S3_READ_WRITE_USERS"
)

// Init registers the ten built-in environment settings and prints the registry
// to standard output. The output includes configured tokens and S3 secrets;
// callers must treat startup logs as sensitive. Invoke it before concurrent use.
func (s *SettingsType) Init() {
	s.Set(ACME_SERVER, "ACME server url", "")
	s.Set(SERVER_DOMAIN, "server domain name", "")
	s.Set(DISK_USAGE_ALLOWED, "Allowed disk usage in percentage", "75")
	s.Set(EXTEND_LIFE_SUPPORT, "Enable extended life support", "false")
	s.Set(DATA_FOLDER, "data folder", "/files")
	s.Set(SERVER_PORT, "server tcp port", "8000")
	s.Set(READ_TOKEN, "Read TOKEN [;]", "")
	s.Set(WRITE_TOKEN, "Write TOKEN [;]", "")
	s.Set(S3_READ_ONLY_USERS, "S3 Read only users [user=key;]", "")
	s.Set(S3_READ_WRITE_USERS, "S3 Read and Write users [user=key;]", "")

	table := tablewriter.NewTable(
		os.Stdout,
		tablewriter.WithHeaderAutoWrap(tw.WrapNone),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithHeaderAutoFormat(tw.On),
		tablewriter.WithRendition(tw.Rendition{
			Symbols: tw.NewSymbols(tw.StyleASCII),
			Settings: tw.Settings{
				Separators: tw.Separators{BetweenRows: tw.On},
			},
		}),
	)
	table.Header("KEY", "Description", "value")
	for key, setting := range s.m {
		table.Append([]string{key, setting.Description, setting.Value})
	}
	table.Render()

}
