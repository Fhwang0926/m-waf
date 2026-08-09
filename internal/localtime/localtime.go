package localtime

import "time"

var kst = time.FixedZone("KST", 9*60*60)

func FormatKST(value any, layout string) string {
	switch typed := value.(type) {
	case time.Time:
		return typed.In(kst).Format(layout)
	case *time.Time:
		if typed != nil {
			return typed.In(kst).Format(layout)
		}
	}
	return ""
}

func ParseKST(layout, value string) (time.Time, error) {
	return time.ParseInLocation(layout, value, kst)
}
