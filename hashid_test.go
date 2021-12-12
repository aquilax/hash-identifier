package hashid

import (
	"reflect"
	"testing"
)

func getIds(hi []HashInfo) []HashID {
	var result []HashID
	for i := range hi {
		result = append(result, hi[i].ID)
	}
	return result
}

func TestIdentify(t *testing.T) {
	tests := []struct {
		hash string
		want []HashID
	}{
		{"C061", []HashID{CRC_16, CRC_16_CCITT, FCS_16, Cisco_Type_7}},
		{"FFFFFF", []HashID{CRC_24, Cisco_Type_7}},
		{"$crc32$11111111:FFFFFFFF", []HashID{CRC_32}},
		{"ghp_AABBCC", []HashID{GitHub_Personal_Access_Token}},
		{"gho_AABBCC", []HashID{GitHub_OAuth_Access_Token}},
		{"ghu_AABBCC", []HashID{GitHub_App_User_To_Server_Token}},
		{"ghs_AABBCC", []HashID{GitHub_App_Server_To_Server_Token}},
		{"ghr_AABBCC", []HashID{GitHub_App_Refresh_Token}},
		{"xoxb-17653672481-19874698323-pdFZKVeTuE8sk7oOcBrzbqgy", []HashID{Slack_Bot_Token}},
		{"xoxp-1234", []HashID{Slack_User_Token}},
		{"xoxe-1-abcdefg", []HashID{Slack_Refresh_Token}},
		{"xoxe.xoxp-2-abcdefg", []HashID{Slack_Config_Access_Token}},
		{"pk_test_4QHSdRjQiwkzokPPCiK33eOq", []HashID{Stripe_Test_Mode_Publishable_Key}},
		{"sk_test_4QHS9UR02FMGKPqdjElznDRI", []HashID{Stripe_Test_Mode_Secret_Key}},
	}

	dp := GetDefaultPrototypes()

	for _, tt := range tests {
		t.Run(tt.hash, func(t *testing.T) {
			got, _ := Identify([]byte(tt.hash), dp)
			hashIds := getIds(got)
			if !reflect.DeepEqual(hashIds, tt.want) {
				t.Errorf("Identify() = %v, want %v", hashIds, tt.want)
			}
		})
	}
}
