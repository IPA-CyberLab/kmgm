package structflags

import (
	"fmt"
	"reflect"
	"time"

	"github.com/urfave/cli/v2"
)

var DurationType = reflect.TypeOf(time.Duration(0))

type Unmarshaler interface {
	UnmarshalFlag(string) error
}

var UnmarshalerType = reflect.TypeOf((*Unmarshaler)(nil)).Elem()

func populateValueFromCliContext(v reflect.Value, c *cli.Context, parsed *ParsedTag) error {
	for v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.CanAddr() {
		if u, ok := v.Addr().Interface().(Unmarshaler); ok {
			if c.IsSet(parsed.Name) {
				flagVal := c.String(parsed.Name)
				if err := u.UnmarshalFlag(flagVal); err != nil {
					return fmt.Errorf("Failed to parse flag %s=%q: %w", parsed.Name, flagVal, err)
				}
			}
			return nil
		}
	}
	if DurationType.AssignableTo(v.Type()) {
		flagVal := c.Duration(parsed.Name)
		v.Set(reflect.ValueOf(flagVal))
		return nil
	}

	switch v.Kind() {
	case reflect.Bool:
		if c.IsSet(parsed.Name) {
			v.SetBool(true)
		}

	case reflect.Int:
		if c.IsSet(parsed.Name) {
			v.SetInt(int64(c.Int(parsed.Name)))
		}

	case reflect.String:
		if c.IsSet(parsed.Name) {
			v.SetString(c.String(parsed.Name))
		}

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			vf := v.Field(i)
			tf := v.Type().Field(i)
			parsedField := Parse(tf.Tag, parsed)
			if parsedField == nil {
				continue
			}

			if err := populateValueFromCliContext(vf, c, parsedField); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("Don't know how to populate type %v from commandline flag.", v.Type())
	}

	return nil
}

func PopulateStructFromCliContext(cfg interface{}, c *cli.Context) error {
	return populateValueFromCliContext(reflect.ValueOf(cfg), c, nil)
}

func populateFlagsFromType(t reflect.Type, parsed *ParsedTag, fs *[]cli.Flag) error {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	pt := reflect.PtrTo(t)
	if pt.Implements(UnmarshalerType) {
		*fs = append(*fs, parsed.ToCliFlag(reflect.Interface))
		return nil
	}
	if t.AssignableTo(DurationType) {
		*fs = append(*fs, parsed.ToDurationFlag())
	}

	switch t.Kind() {
	case reflect.String, reflect.Bool, reflect.Int:
		*fs = append(*fs, parsed.ToCliFlag(t.Kind()))

	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			tf := t.Field(i)

			parsedField := Parse(tf.Tag, parsed)
			if parsedField == nil {
				continue
			}
			if err := populateFlagsFromType(tf.Type, parsedField, fs); err != nil {
				return err
			}
		}
	}
	return nil
}

func PopulateFlagsFromStruct(v interface{}) ([]cli.Flag, error) {
	var fs []cli.Flag
	err := populateFlagsFromType(reflect.TypeOf(v), nil, &fs)
	if err != nil {
		return nil, err
	}
	return fs, nil
}

func MustPopulateFlagsFromStruct(v interface{}) []cli.Flag {
	flags, err := PopulateFlagsFromStruct(v)
	if err != nil {
		panic(err)
	}
	return flags
}
