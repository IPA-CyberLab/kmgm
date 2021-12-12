package structflags

import (
	"fmt"
	"html"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
)

type ParsedTag struct {
	Name    string
	Usage   string
	Aliases []string
	Opts    map[string]struct{}
}

func Parse(tag reflect.StructTag, parent *ParsedTag) *ParsedTag {
	tagstr, ok := tag.Lookup("flags")
	if !ok {
		return nil
	}

	parsed := &ParsedTag{}

	ss := strings.Split(tagstr, ",")
	if len(ss) > 0 {
		parsed.Name = ss[0]
		if parent != nil && parent.Name != "" {
			parsed.Name = fmt.Sprintf("%s.%s", parent.Name, parsed.Name)
		}
	}
	if len(ss) > 1 {
		parsed.Usage = html.UnescapeString(ss[1])
	}
	if len(ss) > 2 {
		aliases := strings.Split(ss[2], ";")
		for _, e := range aliases {
			if e == "" {
				continue
			}
			parsed.Aliases = append(parsed.Aliases, e)
		}
	}
	if len(ss) > 3 {
		parsed.Opts = make(map[string]struct{})
		for _, e := range ss[3:] {
			parsed.Opts[e] = struct{}{}
		}
	}

	return parsed
}

var DurationType = reflect.TypeOf(time.Duration(0))

func (parsed *ParsedTag) ToCliFlag(v reflect.Value) cli.Flag {
	_, required := parsed.Opts["required"]
	_, hidden := parsed.Opts["hidden"]

	if _, ok := parsed.Opts["duration"]; ok {
		return &cli.DurationFlag{
			Name:     parsed.Name,
			Usage:    parsed.Usage,
			Aliases:  parsed.Aliases,
			Required: required,
			Hidden:   hidden,
			// FIXME: default value
		}
	}

	var defaultValue string
	stringLike := false
	if v.Kind() == reflect.String {
		stringLike = true
		defaultValue = v.String()
	} else if v.Type().Implements(UnmarshalerType) {
		stringLike = true
		defaultValue = "" // FIXME
	} else if v.CanAddr() && v.Addr().Type().Implements(UnmarshalerType) {
		stringLike = true
		defaultValue = "" // FIXME
	}
	if stringLike {
		if _, ok := parsed.Opts["path"]; ok {
			return &cli.PathFlag{
				Name:        parsed.Name,
				Usage:       parsed.Usage,
				Aliases:     parsed.Aliases,
				Required:    required,
				Hidden:      hidden,
				Value:       defaultValue,
				DefaultText: defaultValue,
			}
		} else {
			return &cli.StringFlag{
				Name:        parsed.Name,
				Usage:       parsed.Usage,
				Aliases:     parsed.Aliases,
				Required:    required,
				Hidden:      hidden,
				Value:       defaultValue,
				DefaultText: defaultValue,
			}
		}
	}

	switch v.Kind() {
	case reflect.Bool:
		return &cli.BoolFlag{
			Name:     parsed.Name,
			Usage:    parsed.Usage,
			Aliases:  parsed.Aliases,
			Required: required,
			Hidden:   hidden,
			Value:    v.Bool(),
		}

	case reflect.Int:
		return &cli.IntFlag{
			Name:     parsed.Name,
			Usage:    parsed.Usage,
			Aliases:  parsed.Aliases,
			Required: required,
			Hidden:   hidden,
			Value:    int(v.Int()),
		}

	default:
		log.Panicf("ToCliFlag: unknown kind %v", v.Kind())
		return nil
	}
}
