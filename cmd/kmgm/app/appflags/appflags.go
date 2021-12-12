package appflags

type AppFlags struct {
	BaseDir        string `yaml:"baseDir" flags:"basedir,The root directory storing all kmgm data,"`
	Profile        string `yaml:"profile" flags:"profile,Name of the profile to operate against"`
	Config         string `flags:"config,Read the specified YAML config file instead of interactive prompt.,,path"`
	LogJson        bool   `flags:"log-json,Format logs in json"`
	NoGeoIp        bool   `flags:"no-geo-ip,Disable querying ip-api.com for geolocation data"`
	LogLocation    bool   `flags:"log-location,Annotate logs with code location where the log was output"`
	NoDefault      bool   `yaml:"noDefault" flags:"no-default,Disable populating default values on non-interactive mode,"`
	Verbose        bool   `flags:"verbose,Enable verbose output"`
	NonInteractive bool   `flags:"non-interactive,Use non-interactive frontend&comma; which auto proceeds with default answers."`
}
