package fetch

import "testing"

func TestParseIconFileMatchesGoFOFASelection(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "first standard icon wins",
			html: `<link rel="apple-touch-icon" sizes="180x180" href="/apple.png">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">`,
			want: "/favicon-32x32.png",
		},
		{
			name: "shortcut icon token matches",
			html: `<link rel="shortcut Icon" href="/shortcut.ico">`,
			want: "/shortcut.ico",
		},
		{
			name: "icon substring does not match",
			html: `<link rel="apple-touch-icon" href="/apple.png">`,
			want: "/favicon.ico",
		},
		{
			name: "blank first icon is skipped",
			html: `<link rel="icon" href="  "><link rel="icon" href="/valid.ico">`,
			want: "/valid.ico",
		},
		{
			name: "default icon",
			html: `<link rel="stylesheet" href="/style.css">`,
			want: "/favicon.ico",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseIconFile(tt.html); got != tt.want {
				t.Fatalf("parseIconFile() = %q, want %q", got, tt.want)
			}
		})
	}
}
