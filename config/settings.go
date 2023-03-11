package config

import (
	"github.com/olekukonko/tablewriter"
	"os"
)

type SettingsType struct {
	m map[string]SettingType
}

type SettingType struct {
	Description string
	Value       string
}

var Settings = &SettingsType{m: make(map[string]SettingType)}

func (s *SettingsType) Get(id string) string {
	return s.m[id].Value
}

func (s *SettingsType) Has(id string) bool {
	return len(s.m[id].Value) > 0
}

func (s *SettingsType) Set(id string, description string, defaultValue string) {
	if value, ok := os.LookupEnv(id); ok {
		s.m[id] = SettingType{Description: description, Value: value}
	}else{
		s.m[id] = SettingType{Description: description, Value: defaultValue}
	}
}


const (
	ACME_SERVER   = "ACME_SERVER"
	SERVER_DOMAIN = "SERVER_DOMAIN"
	DISK_USAGE_ALLOWED = "DISK_USAGE_ALLOWED"
	EXTEND_LIFE_SUPPORT = "EXTEND_LIFE_SUPPORT"
	DATA_FOLDER = "DATA_FOLDER"
	SERVER_PORT = "SERVER_PORT"
	READ_TOKEN = "READ_TOKEN"
	WRITE_TOKEN = "WRITE_TOKEN"
	S3_READ_TOKEN = "S3_READ_TOKEN"
	S3_WRITE_TOKEN = "S3_WRITE_TOKEN"
)

func (s *SettingsType) Init() {
	s.Set(ACME_SERVER, "ACME server url", "")
	s.Set(SERVER_DOMAIN, "server domain name","")
	s.Set(DISK_USAGE_ALLOWED, "Allowed disk usage in percentage","75")
	s.Set(EXTEND_LIFE_SUPPORT, "Enable extended life support","false")
	s.Set(DATA_FOLDER, "data folder","/files")
	s.Set(SERVER_PORT, "server tcp port","8000")
	s.Set(READ_TOKEN, "Read TOKEN [;]","")
	s.Set(WRITE_TOKEN, "Write TOKEN [;]","")
	s.Set(S3_READ_TOKEN, "S3 Read TOKEN [user=key;]","")
	s.Set(S3_WRITE_TOKEN, "S3 Write TOKEN [user=key;]","")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetAutoWrapText(false)
	table.SetRowLine(true)
	table.SetAutoFormatHeaders(true)
	table.SetHeader([]string{"KEY", "Description", "value"})
	for key, setting := range s.m {
		table.Append([]string{key, setting.Description, setting.Value})
	}
	table.Render()

}
