package structflags

import (
	"fmt"
	"html"
	"log"
	"reflect"
	"strings"

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

func (parsed *ParsedTag) ToCliFlag(k reflect.Kind) cli.Flag {
	_, required := parsed.Opts["required"]
	_, hidden := parsed.Opts["hidden"]

	switch k {
	case reflect.Bool:
		return &cli.BoolFlag{
			Name:     parsed.Name,
			Usage:    parsed.Usage,
			Aliases:  parsed.Aliases,
			Required: required,
			Hidden:   hidden,
		}

	case reflect.String, reflect.Interface:
		if _, ok := parsed.Opts["path"]; ok {
			return &cli.PathFlag{
				Name:     parsed.Name,
				Usage:    parsed.Usage,
				Aliases:  parsed.Aliases,
				Required: required,
				Hidden:   hidden,
			}
		} else {
			return &cli.StringFlag{
				Name:     parsed.Name,
				Usage:    parsed.Usage,
				Aliases:  parsed.Aliases,
				Required: required,
				Hidden:   hidden,
			}
		}

	default:
		log.Panicf("ToCliFlag: unknown kind %v", k)
		return nil
	}
}

func (parsed *ParsedTag) ToDurationFlag() cli.Flag {
	_, required := parsed.Opts["required"]
	_, hidden := parsed.Opts["hidden"]

	return &cli.DurationFlag{
		Name:     parsed.Name,
		Usage:    parsed.Usage,
		Aliases:  parsed.Aliases,
		Required: required,
		Hidden:   hidden,
	}
}
