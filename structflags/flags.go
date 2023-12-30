package structflags

import (
	"fmt"
	"reflect"

	"github.com/urfave/cli/v2"
)

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
		if c.IsSet(parsed.Name) {
			flagVal := c.Duration(parsed.Name)
			v.Set(reflect.ValueOf(flagVal))
		}
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

func populateFlagsFromValue(v reflect.Value, parsed *ParsedTag, fs *[]cli.Flag) error {
	for v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Type().Implements(UnmarshalerType) ||
		v.CanAddr() && v.Addr().Type().Implements(UnmarshalerType) {
		// make it a single flag if unmarshallable
		*fs = append(*fs, parsed.ToCliFlag(v))
		return nil
	}

	if v.Kind() == reflect.Struct {
		// recurse if not unmarshallable struct
		for i := 0; i < v.NumField(); i++ {
			parsedField := Parse(v.Type().Field(i).Tag, parsed)

			// only process fields if tagged
			if parsedField == nil {
				continue
			}

			fv := v.Field(i)

			// if the field value is nil ptr, zero construct a struct
			if fv.Type().Kind() == reflect.Ptr && fv.IsNil() {
				ft := v.Type().Field(i).Type.Elem()
				fv = reflect.New(ft)
			}

			if err := populateFlagsFromValue(fv, parsedField, fs); err != nil {
				return err
			}
		}

		return nil
	}

	*fs = append(*fs, parsed.ToCliFlag(v))
	return nil
}

func PopulateFlagsFromStruct(s interface{}) ([]cli.Flag, error) {
	var fs []cli.Flag

	if err := populateFlagsFromValue(reflect.ValueOf(s), nil, &fs); err != nil {
		return nil, err
	}

	return fs, nil
}

func MustPopulateFlagsFromStruct(s interface{}) []cli.Flag {
	flags, err := PopulateFlagsFromStruct(s)
	if err != nil {
		panic(err)
	}
	return flags
}
