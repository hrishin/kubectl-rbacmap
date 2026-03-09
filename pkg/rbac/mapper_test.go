package rbac

import (
	"testing"
)

func TestMatchAWSARN(t *testing.T) {
	tests := []struct {
		name      string
		targetArn string
		mappedArn string
		expected  bool
	}{
		{
			name:      "exact match",
			targetArn: "arn:aws:iam::123456789012:user/admin",
			mappedArn: "arn:aws:iam::123456789012:user/admin",
			expected:  true,
		},
		{
			name:      "case insensitive match",
			targetArn: "ARN:AWS:IAM::123456789012:USER/ADMIN",
			mappedArn: "arn:aws:iam::123456789012:user/admin",
			expected:  true,
		},
		{
			name:      "mismatch",
			targetArn: "arn:aws:iam::123456789012:user/admin",
			mappedArn: "arn:aws:iam::123456789012:user/other",
			expected:  false,
		},
		{
			name:      "sts assumed role match to base role",
			targetArn: "arn:aws:sts::123456789012:assumed-role/MyEksRole/my-session-name",
			mappedArn: "arn:aws:iam::123456789012:role/MyEksRole",
			expected:  true,
		},
		{
			name:      "sts assumed role mismatch base role",
			targetArn: "arn:aws:sts::123456789012:assumed-role/OtherRole/my-session-name",
			mappedArn: "arn:aws:iam::123456789012:role/MyEksRole",
			expected:  false,
		},
		{
			name:      "invalid sts format gracefully fails",
			targetArn: "arn:aws:sts::123456789012:assumed-role",
			mappedArn: "arn:aws:iam::123456789012:role/MyEksRole",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchAWSARN(tt.targetArn, tt.mappedArn)
			if result != tt.expected {
				t.Errorf("matchAWSARN(%q, %q) = %v; want %v", tt.targetArn, tt.mappedArn, result, tt.expected)
			}
		})
	}
}
