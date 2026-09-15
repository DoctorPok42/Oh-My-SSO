package entstore

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
