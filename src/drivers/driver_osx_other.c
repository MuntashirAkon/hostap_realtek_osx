#define Boolean Boolean2
#include <IOKit/IOKitLib.h>
#undef Boolean

#include "includes.h"
#include <sys/types.h>
#include "common.h"
#include "driver.h"
#include "driver_osx_other.h"
#include <string.h>
#include <mach/mach_port.h>
#include <eloop.h>
#include <wpa_debug.h>


struct information_struct
{
	unsigned int id;
	int in_size;
	int out_size;
	int unk2;
	char buf[2500];
};
struct scan_result_struct
{
	u8 ssid[35];
  	signed char channel;
  	u8 bssid[6];
  	u8 unk1[526];
  	int noise;
  	u16 caps;
  	u16 ie_len;
  	char extra[1024];
};
struct wpa_key_struct
{
	u32 k[32];
	size_t key_len;
	int key_idx;
	u8 addr[6];
	u8 seq[6];
	size_t seq_len;
};

kern_return_t FindRTL8180(io_connect_t *pConnect);
int ISRTL8180Enabled(io_connect_t connect);
int QueryInformation(io_connect_t connect, unsigned int id, void *output);
int GetBSSID(io_connect_t connect, u8 *bssid);
int GetNetworkName(io_connect_t connect, u8 *ssid);
int SetInformationValue(io_connect_t connect, unsigned int id, unsigned int value);
int SetInformation(io_connect_t connect, unsigned int id, const void *buf, size_t len);
int GetAvailableNetworkNumber(io_connect_t connect, unsigned int *result);
int GetAvailableNetworksFromDriver(io_connect_t connect, unsigned int index, struct scan_result_struct *scan_result);
int SetWEPKey(io_connect_t connect, int key_idx, const u8 *wep_key, size_t len);
int RealtekWirelessAssociate(io_connect_t connect, struct wpa_driver_associate_params *params);
int SetNetworkName(io_connect_t connect, const u8 *ssid, size_t ssid_len);
int SetWPAKey(io_connect_t connect, const char *key);
int SwitchToAPMode(io_connect_t connect, int newmode)
{
	int result = -1;
	printf("Realtek:: %s ==>\n", __func__);
	result = SetInformationValue(connect, OID_RT_AP_SWITCH_INTO_AP_MODE, newmode);
	//SetInformationValue(connect, OID_RT_EXTAP_SWITCH_INTO_AP_MODE, newmode);
	//SetInformationValue(connect, OID_RT_AP_WDS_MODE, 1);
	return result;
}

kern_return_t FindRTL8180(io_connect_t *pConnect)
{
	kern_return_t result;
	size_t i;
	mach_port_t masterPort;
	io_connect_t connect;
	io_object_t service;
	CFMutableDictionaryRef matching;
	io_iterator_t iterator;
	const char *services[] = { "RtWlanU", "RtWlanU1827" };

	printf("Realtek:: %s ==>\n", __func__);
	result = IOMasterPort(MACH_PORT_NULL, &masterPort);
	if (!result)
	{
		for (i = 0; i < sizeof(services) / sizeof(services[0]); i++)
		{
			matching = IOServiceMatching(services[i]);
			if (matching)
			{
				result = IOServiceGetMatchingServices(masterPort, matching, &iterator);
				if (!result)
				{
					service = IOIteratorNext(iterator);
					if (service)
					{
						result = IOServiceOpen(service, mach_task_self_, 0, &connect);
						break;
					}
					IOObjectRelease(iterator);
				}
			}
		}
		if (matching && !result && service)
		{
			*pConnect = connect;
		}
		else
		{
			wpa_printf(MSG_ERROR, "IOServiceGetMatchingServices returned %d", result);
			printf("IOServiceGetMatchingServices returned %d", result);
			mach_port_deallocate(mach_task_self_, masterPort);
		}
	}
	return result;
}
int ISRTL8180Enabled(io_connect_t connect)
{
	int result;

	result = 0;
	if (QueryInformation(connect, OID_RT_NETWORK_STATUS, &result) == -1)
		result = 0;
	return result;
}
int QueryInformation(io_connect_t connect, unsigned int id, void *output)
{
	kern_return_t result;
	struct information_struct info;
	size_t infoCnt;

	infoCnt = sizeof(struct information_struct);
	printf("Realtek:: %s (0x%X)==>\n", __func__, id);
	memset(&info, 0, sizeof(struct information_struct));
	info.id = id;
	info.in_size = sizeof(info.buf);
	info.out_size = 0;
	info.unk2 = 0;
	result = IOConnectCallStructMethod(connect, 9, &info, sizeof(info), &info, &infoCnt);
	if (!info.out_size)
		return -1;
	if (result)
		return -1;
	memcpy(output, info.buf, info.out_size);
	if (id == OID_RT_802_11_SSID)
		printf("Realtek:: %s (Len=%d)\n", (const char*)output, info.out_size);
	return info.out_size;
}
int GetBSSID(io_connect_t connect, u8 *bssid)
{
	return QueryInformation(connect, OID_802_11_BSSID, bssid);
}
int GetNetworkName(io_connect_t connect, u8 *ssid)
{
	return QueryInformation(connect, OID_RT_802_11_SSID, ssid);
}
int SetInformationValue(io_connect_t connect, unsigned int id, unsigned int value)
{
	kern_return_t result;
	struct information_struct info;
	size_t infoCnt;

	infoCnt = sizeof(struct information_struct);
	info.in_size = sizeof(info.buf);
	memcpy(info.buf, &value, sizeof(value));
	info.id = id;
	info.out_size = 0;
	info.unk2 = 0;
	result = IOConnectCallStructMethod(connect, 10, &info, sizeof(info), &info, &infoCnt);
	return result == 0;
}
int SetInformation(io_connect_t connect, unsigned int id, const void *buf, size_t len)
{
	kern_return_t result;
	struct information_struct info;
	size_t infoCnt;

	infoCnt = sizeof(struct information_struct);
	info.in_size = len;
	memcpy(info.buf, buf, len);
	info.id = id;
	info.out_size = 0;
	info.unk2 = 0;
	result = IOConnectCallStructMethod(connect, 10, &info, sizeof(info), &info, &infoCnt);
	return result == 0;
}
int GetAvailableNetworkNumber(io_connect_t connect, unsigned int *result)
{
	QueryInformation(connect, OID_RT_GET_BSS_NUMBER, result);
	return 1;
}
int GetAvailableNetworksFromDriver(io_connect_t connect, unsigned int index, struct scan_result_struct *scan_result)
{
	size_t outputStructCnt;
	uint64_t input;
	kern_return_t ret;

	input = index;
	outputStructCnt = sizeof(struct scan_result_struct);
	ret = IOConnectCallMethod(connect, 0, &input, 1, NULL, 0, NULL, NULL, scan_result, &outputStructCnt);
	if (!ret)
		return 1;
	printf("GetAvailableNetworksFromDriver() failed\n");
	return 0;
}
int SetWEPKey(io_connect_t connect, int key_idx, const u8 *wep_key, size_t len)
{
	struct wpa_key_struct buf;

	buf.key_idx = key_idx;
	printf("SetWEPKey Index(%d)===>\n", key_idx);
	if (len <= 152)
		memcpy(&buf, wep_key, len); // memcpy_chk
	buf.key_len = len;
	wpa_hexdump(MSG_MSGDUMP, "SetWEPKey", (const u8*)&buf, len);
	if (SetInformation(connect, OID_802_11_ADD_WEP, &buf, sizeof(buf)) == -1)
		return -1;
	printf("SetWEPKey <===\n");
	return 1;
}
int RealtekWirelessAssociate(io_connect_t connect, struct wpa_driver_associate_params *params)
{
	int i;
	int psk;
	int algo;
	int result;

	printf("===================================================\n");
	if (params->bssid)
		printf(
			"params->bssid=0x%02X-0x%02X-0x%02X-0x%02X-0x%02X-0x%02X\n",
			params->bssid[0],
			params->bssid[1],
			params->bssid[2],
			params->bssid[3],
			params->bssid[4],
			params->bssid[5]);
	if (params->ssid_len)
		printf("params->ssid=%s, len=%zd\n", params->ssid, params->ssid_len);
	printf("params->freq=%d\n", params->freq.freq);
	if (params->wpa_ie_len)
	{
		printf("params->wpa_ie_len=%zd\n", params->wpa_ie_len);
		for (i = 0; i < params->wpa_ie_len; ++i)
		{
			if (!(i & 0xF))
				printf("\n");
			printf("0x%02X ", params->wpa_ie[i]);
		}
	}
	printf("\n");
	printf("params->wpa_proto=%d\n", params->wpa_proto);
	printf("params->pairwise_suite=%d\n", params->pairwise_suite);
	printf("params->group_suite=%d\n", params->group_suite);
	printf("params->key_mgmt_suite=%d\n", params->key_mgmt_suite);
	printf("params->auth_alg=%d\n", params->auth_alg);
	printf("params->mode=%d\n", params->mode);
	if (params->wep_key_len[0])
		printf("params->wep_key_len[0]=%zd\n", params->wep_key_len[0]);
	if (params->wep_key_len[1])
		printf("params->wep_key_len[0]=%zd\n", params->wep_key_len[1]);
	if (params->wep_key_len[2])
		printf("params->wep_key_len[0]=%zd\n", params->wep_key_len[2]);
	if (params->wep_key_len[3])
		printf("params->wep_key_len[0]=%zd\n", params->wep_key_len[3]);
	printf("params->wep_tx_keyidx=%d\n", params->wep_tx_keyidx);
	printf("params->mgmt_frame_protection=%d\n", params->mgmt_frame_protection);
    if (params->ft_ies_len)
        printf("params->ft_ies_len=%zd\n", params->ft_ies_len);
    if (params->ft_md)
        printf("params->ft_md[0]=0x%02X\n", params->ft_md[0]);
	if (params->passphrase)
		printf("params->passphrase[0]=0x%02X\n", params->passphrase[0]);
	if (params->psk)
		printf("params->psk[0]=0x%02X\n", params->psk[0]);
	printf("params->drop_unencrypted=%d\n", params->drop_unencrypted);
	if (params->prev_bssid)
		printf("params->prev_bssid[0]=0x%02X\n", params->prev_bssid[0]);
	printf("params->wps=%d\n", params->wps);
	printf("params->p2p=%d\n", params->p2p);
	printf("params->uapsd=%d\n", params->uapsd);
	printf("===================================================\n");
	SetInformationValue(connect, OID_802_11_DISASSOCIATE, 0);
	SetNetworkName(connect, params->ssid, params->ssid_len);
	psk = 1;
	if ((params->auth_alg & 2) == 0)
		psk = 0;
	SetInformationValue(connect, OID_RT_SHAREDKEY_AUTHENTICATION, psk);
	algo = 0;
	if (params->wpa_proto)
	{
		if (params->wpa_proto == 2)
		{
			printf("1.RSN\n");
			if (params->key_mgmt_suite)
			{
				if (params->key_mgmt_suite == WPA_KEY_MGMT_PSK)
				{
					if (params->pairwise_suite == CIPHER_TKIP)
					{
						algo = 5;
						printf("1.3 WPA2-PSK TKIP\n");
					}
					else if (params->pairwise_suite == CIPHER_CCMP)
					{
						algo = 6;
						printf("1.4 WPA2-PSK AES\n");
					}
					else
					{
						printf("1.5 WPA2-PSK: error pairwise_suite=%d\n", params->pairwise_suite);
					}
				}
				else
				{
					printf("1.6 RSN: error key_mgmt_suite=%d\n", params->key_mgmt_suite);
				}
			}
			else if (params->pairwise_suite == CIPHER_TKIP)
			{
				algo = 9;
				printf("1.1 RSN-1X TKIP\n");
			}
			else if (params->pairwise_suite == CIPHER_CCMP)
			{
				algo = 10;
				printf("1.1 RSN-1X AES\n");
			}
			else
			{
				printf("1.2 RSN-1X: error pairwise_suite=%d\n", params->pairwise_suite);
			}
		}
		else if (params->wpa_proto == 1)
		{
			printf("2.WPA\n");
			if (params->key_mgmt_suite)
			{
				if (params->key_mgmt_suite == WPA_KEY_MGMT_PSK)
				{
					if (params->pairwise_suite == CIPHER_TKIP)
					{
						algo = 3;
						printf("2.3 WPA-PSK TKIP\n");
					}
					else if (params->pairwise_suite == CIPHER_CCMP)
					{
						algo = 4;
						printf("2.4 WPA-PSK AES\n");
					}
					else
					{
						printf("2.6 WPA: error key_mgmt_suite=%d\n", params->key_mgmt_suite);
					}
				}
			}
			else if (params->pairwise_suite == CIPHER_TKIP)
			{
				algo = 7;
				printf("2.1 WPA-1X TKIP\n");
			}
			else if (params->pairwise_suite == CIPHER_CCMP)
			{
				algo = 8;
				printf("2.1 WPA-1X AES\n");
			}
			else
			{
				printf("2.2 WPA-1X: error pairwise_suite=%d\n", params->pairwise_suite);
			}
		}
	}
	else
	{
		printf("0. OPEN or WEP\n");
		if (params->pairwise_suite != CIPHER_WEP40 && params->pairwise_suite != CIPHER_WEP104)
		{
			algo = 0;
			SetInformationValue(connect, OID_RT_SET_DEFAULT_KEY_ID, 0);
		}
		else if (params->key_mgmt_suite == WPA_KEY_MGMT_IEEE8021X_NO_WPA)
		{
			printf("0.1  WEP 802.1X\n");
			if (params->pairwise_suite == CIPHER_WEP104)
				algo = 12;
			else
				algo = 11;
		}
		else if (params->key_mgmt_suite == WPA_KEY_MGMT_NONE &&
			(params->wep_key_len[0] || params->wep_key_len[1] || params->wep_key_len[2] || params->wep_key_len[3]))
		{
			printf("0.2  OPEN-WEP or SHARD-WEP\n");
			SetInformationValue(connect, OID_RT_SET_DEFAULT_KEY_ID, params->wep_tx_keyidx);
			for (i = 0; i < 4; ++i)
			{
				if (params->wep_key[i])
					SetWEPKey(connect, params->wep_tx_keyidx, params->wep_key[i], params->wep_key_len[i]);
			}
			if (params->pairwise_suite == CIPHER_WEP104)
				algo = 2;
			else
				algo = 1;
		}
	}
	SetInformationValue(connect, OID_802_11_INFRASTRUCTURE_MODE, params->mode);
    if (params->mode == 2)
	{
		SwitchToAPMode(connect, 1);
		SetInformationValue(connect, OID_RT_AP_WDS_MODE, 0);
		SetInformationValue(connect, OID_802_11_INFRASTRUCTURE_MODE, 1);
		SetInformationValue(connect, OID_RT_AUTO_SELECT_CHANNEL, 0);
		SetInformationValue(connect, OID_RT_SET_CHANNEL, (params->freq.freq - 2407) / 5);
		SetInformationValue(connect, OID_RT_SET_BCN_INTVL, 100);
	}
	if (params->passphrase)
		SetWPAKey(connect, params->passphrase);
	SetInformationValue(connect, OID_RT_ENCRYPTION_ALGORITHM, algo);
	//SetInformationValue(connect, OID_RT_EXTAP_SET_ENCRYPTION_ALGORITHM, algo);
	result = SetInformationValue(connect, OID_RT_SCAN_SSID_AND_LINK, 0);
    if (params->key_mgmt_suite != WPA_KEY_MGMT_NONE) // BUG Alert: originally it was ==
		result = SetWPAKey(connect, params->passphrase);
	SetInformationValue(connect, OID_RT_AP_SET_BEACON_START, 1);

	return result;
}
int SetNetworkName(io_connect_t connect, const u8 *ssid, size_t ssid_len)
{
	struct network_name
	{
		char ssid[128];
		size_t ssid_len;
	};
	struct network_name buf;
	if (ssid_len <= 128)
		memcpy(buf.ssid, ssid, ssid_len); // memcpy_chk
	buf.ssid_len = ssid_len;
	if (SetInformation(connect, OID_RT_802_11_SSID, &buf, sizeof(buf)) == -1)
		return -1;
	return 1;
}
int SetWPAKey(io_connect_t connect, const char *key)
{
	size_t len;
	struct wpa_key_struct buf;

	len = strlen(key);
	buf.key_idx = 0;
	printf("SetWPAKey Len=%zd ===>\n", len);
	if (len <= sizeof(buf))
		memcpy(&buf, key, len); // memcpy_chk
	buf.key_len = len;
	printf("WPAPSKKey length = %zd, Key = %s\n", len, key);
	if (SetInformation(connect, OID_RT_AP_SET_PASSPHRASE, &buf, sizeof(buf)) == -1)
		return -1;
	//SetInformation(connect, OID_RT_EXTAP_SET_PASSPHRASE, &buf, sizeof(buf));
	printf("SetWPAKey <===\n");
	return 1;
}



struct wpa_driver_osx_other_data
{
	void *ctx;
	io_connect_t connect;
	int unk1;
	u8 mac[6];
	int apmode;
	int apfreq;
};

int wpa_driver_osx_other_get_bssid(void *priv, u8 *bssid);

void wpa_driver_osx_other_add_scan_entry(struct wpa_scan_results *results, const struct scan_result_struct *scan_result)
{
	struct wpa_scan_res **re;
	struct wpa_scan_res *res;

	res = (struct wpa_scan_res*)os_zalloc(scan_result->ie_len + sizeof(struct wpa_scan_res));
	if (res)
	{
		memcpy(res->bssid, scan_result->bssid, sizeof(res->bssid));
		res->freq = 5 * scan_result->channel + 2407;
		res->caps = scan_result->caps;
		res->noise = scan_result->noise;
		memcpy((char*)res + sizeof(struct wpa_scan_res), scan_result->extra, scan_result->ie_len);
		res->ie_len = scan_result->ie_len;
		re = (struct wpa_scan_res**)realloc(results->res, sizeof(struct wpa_scan_res*) * (results->num + 1));
		if (re)
		{
			re[results->num++] = res;
			results->res = re;
		}
		else
		{
			free(res);
		}
	}
}
void wpa_driver_osx_other_scan_timeout(void* eloop_data, void* user_ctx)
{
	struct wpa_driver_osx_other_data *data;
	int result;

	data = (struct wpa_driver_osx_other_data*)eloop_data;
	result = 0;
	printf("Realtek:: %s ==>\n", __func__);
	QueryInformation(data->connect, OID_RT_GET_SCAN_IN_PROGRESS, &result);
	if (result)
		eloop_register_timeout(3, 0, wpa_driver_osx_other_scan_timeout, data, data->ctx);
	else
		wpa_supplicant_event(user_ctx, EVENT_SCAN_RESULTS, NULL);
}
void wpa_driver_osx_other_assoc_timeout(void *eloop_data, void* user_ctx)
{
	struct wpa_driver_osx_other_data *data;
	union wpa_event_data event;
	u8 bssid[6];

	data = (struct wpa_driver_osx_other_data*)eloop_data;
	printf("Realtek:: %s ==>\n", __func__);
	wpa_driver_osx_other_get_bssid(data, bssid);
	if (!memcmp(bssid, "\x22\x22\x22\x22\x22\x22", 6))
		eloop_register_timeout(1, 0, wpa_driver_osx_other_assoc_timeout, data, data->ctx);
	else
	{
		if (data->apmode)
		{
			memset(&event, 0, sizeof(event));
			event.assoc_info.addr = data->mac;
			event.assoc_info.freq = data->apfreq;
			wpa_supplicant_event(user_ctx, EVENT_ASSOC, &event);
		}
		else
		{
			wpa_supplicant_event(user_ctx, EVENT_ASSOC, NULL);
		}
	}
}




int wpa_driver_osx_other_get_bssid(void *priv, u8 *bssid)
{
	struct wpa_driver_osx_other_data *data;
	u8 buf[6];

	data = (struct wpa_driver_osx_other_data *)priv;
	printf("Realtek:: %s ==>\n", __func__);
	GetBSSID(data->connect, buf);
	memcpy(bssid, buf, sizeof(buf));
	return 0;
}
int wpa_driver_osx_other_get_ssid(void *priv, u8 *ssid)
{
	struct wpa_driver_osx_other_data *data;
	u8 buf[128];
	int len;

	data = (struct wpa_driver_osx_other_data *)priv;
	printf("Realtek:: %s ==>\n", __func__);
	len = GetNetworkName(data->connect, buf);
	if (len > 0)
	{
		memcpy(ssid, buf, len);
		printf("Realtek:: %s ==>\n", buf);
	}

	return len;
}
int wpa_driver_osx_other_set_key(const char *ifname, void *priv, enum wpa_alg alg,
			    const u8 *addr, int key_idx,
			    int set_tx, const u8 *seq, size_t seq_len,
			    const u8 *key, size_t key_len)
{
	int result;
	size_t i;
	size_t len;
	struct wpa_key_struct wpa_key;
	u8 wep_hex_key[28];
	struct wpa_driver_osx_other_data *data;

	result = -1;
	data = (struct wpa_driver_osx_other_data *)priv;
	printf("Realtek:: %s: %d , alg=%d, key_len=%zd ==>\n", __func__, key_idx, alg, key_len);
	if (addr)
		printf("addr: [0x%02X-0x%02X-0x%02X-0x%02X-0x%02X-0x%02X)\n",
				addr[0],
				addr[1],
				addr[2],
				addr[3],
				addr[4],
				addr[5]);
	if (key_len)
	{
		for (i = 0; i < key_len; ++i)
			printf("0x%02X ", key[i]);
		printf("\n");
	}
	if (seq_len)
	{
		printf("seq_len=%zd seq:\n", seq_len);
		for (i = 0; i < seq_len; ++i)
			printf("0x%02X ", seq[i]);
		printf("\n");
	}
	if (alg != WPA_ALG_NONE)
	{
		if (alg == WPA_ALG_WEP)
		{
			len = 0;
			memset(wep_hex_key, 0, sizeof(wep_hex_key));
			printf("SetKey: WEP key_idx(%d)===>\n", key_idx);
			if (key_len != 5 && key_len != 13)
			{
				if (key_len <= sizeof(wep_hex_key))
					memcpy(wep_hex_key, key, key_len); // memcpy_chk
				len = key_len;
			}
			else
			{
				u8 hex_low, hex_high;

				for (i = 0; i < key_len; ++i)
				{
					hex_high = key[i] >> 4;
					hex_low = key[i] & 0xF;
					if (hex_high > 9)
						hex_high = hex_high - 10 + 'a';
					else
						hex_high += '0';
					if (hex_low > 9)
						hex_low = hex_low - 10 + 'a';
					else
						hex_low += '0';
					wep_hex_key[2 * i] = hex_high;
					wep_hex_key[2 * i + 1] = hex_low;
				}
				len = 2 * key_len;
			}
			wpa_hexdump(MSG_MSGDUMP, "SetKey: WEP", wep_hex_key, len);
			if (addr)
			{
				printf("SetKey: OID_RT_SET_DEFAULT_KEY_ID \n");
				SetInformationValue(data->connect, OID_RT_SET_DEFAULT_KEY_ID, key_idx);
			}
			SetWEPKey(data->connect, key_idx, wep_hex_key, len);
			printf("SetKey: WEP <===\n");
			result = 0;
		}
		else if (alg != WPA_ALG_TKIP && alg != WPA_ALG_CCMP && alg != WPA_ALG_PMK)
		{
			wpa_printf(MSG_DEBUG, "OSX: Unsupported set_key alg %d", alg);
			result = -1;
		}
		else
		{
			printf("SetKey:WPA ===>\n");
			memset(&wpa_key, 0, sizeof(struct wpa_key_struct));
			wpa_key.key_idx = key_idx;
			if (alg == WPA_ALG_TKIP)
			{
				const u32 *tkip_k = (const u32*)key;
				wpa_key.k[0] = tkip_k[0];
				wpa_key.k[1] = tkip_k[1];
				wpa_key.k[2] = tkip_k[2];
				wpa_key.k[3] = tkip_k[3];
				wpa_key.k[4] = tkip_k[6];
				wpa_key.k[5] = tkip_k[7];
				wpa_key.k[6] = tkip_k[4];
				wpa_key.k[7] = tkip_k[5];
			}
			else
			{
				if (key_len <= sizeof(struct wpa_key_struct))
					memcpy(&wpa_key, key, key_len); // memcpy_chk
			}
			wpa_key.key_len = key_len;
			memcpy(wpa_key.addr, addr, 6);
			wpa_key.seq_len = seq_len;
			if (seq_len <= 6)
				memcpy(wpa_key.seq, seq, seq_len); // memcpy_chk
			if (SetInformation(data->connect, OID_802_11_ADD_KEY, &wpa_key, sizeof(wpa_key)) == -1)
			{
				result = -1;
			}
			else
			{
				printf("SetKey:WPA <===\n");
				result = 0;
			}
		}
	}

	return result;
}
int wpa_driver_osx_other_scan(void *priv, struct wpa_driver_scan_params *params)
{
	struct wpa_driver_osx_other_data *data;

	data = (struct wpa_driver_osx_other_data *)priv;
	printf("Realtek:: %s ==>\n", __func__);
	printf("ScanWithoutLink ===>\n");
	if (SetInformationValue(data->connect, OID_RT_802_11_BSSID_LIST_SCAN, 0) == -1)
		return -1;
	printf("ScanWithoutLink <===\n");
	eloop_register_timeout(3, 0, wpa_driver_osx_other_scan_timeout, data, data->ctx);
	return 0;
}
struct wpa_scan_results * wpa_driver_osx_other_get_scan_results(void *priv)
{
	struct wpa_driver_osx_other_data *data;
	struct scan_result_struct scan_result;
	unsigned int count;
	unsigned int i;
	struct wpa_scan_results *results;

	data = (struct wpa_driver_osx_other_data *)priv;
	printf("Realtek:: %s ==>\n", __func__);
	GetAvailableNetworkNumber(data->connect, &count);
	printf("wpa_driver_osx_other_get_scan_results:: num=%d\n", count);
	results = (struct wpa_scan_results*)os_zalloc(sizeof(struct wpa_scan_results));
	if (!results)
		return NULL;
	for (i = 0; i < count; i++)
	{
		memset(&scan_result, 0, sizeof(scan_result));
		if (GetAvailableNetworksFromDriver(data->connect, i, &scan_result))
			wpa_driver_osx_other_add_scan_entry(results, &scan_result);
	}

	return results;
}
int wpa_driver_osx_other_associate(void *priv,
			      struct wpa_driver_associate_params *params)
{
	struct wpa_driver_osx_other_data *data;

	data = (struct wpa_driver_osx_other_data *)priv;
	printf("Realtek:: %s ==>\n", __func__);
	RealtekWirelessAssociate(data->connect, params);
	eloop_cancel_timeout(wpa_driver_osx_other_assoc_timeout, data, data->ctx);
	if (params->mode == 2)
	{
		data->apmode = 1;
		data->apfreq = params->freq.freq;
	}
	else
	{
		data->apmode = 0;
	}
	eloop_register_timeout(0, 0, wpa_driver_osx_other_assoc_timeout, data, data->ctx);
	return 0;
}

void * wpa_driver_osx_other_init(void *ctx, const char *ifname)
{
	io_connect_t connect;
	struct wpa_driver_osx_other_data *data;

	printf("Realtek:: %s ==>\n", __func__);
	if (FindRTL8180(&connect))
		return NULL;
	data = os_zalloc(sizeof(struct wpa_driver_osx_other_data));
	if (data)
	{
		data->ctx = ctx;
		data->connect = connect;
		if (ISRTL8180Enabled(data->connect) != 1)
		{
			free(data);
			return NULL;
		}
		QueryInformation(data->connect, 0x1010102, data->mac);
		return data;
	}
	SwitchToAPMode(data->connect, 0);
	return NULL;
}
void wpa_driver_osx_other_deinit(void *priv)
{
	struct wpa_driver_osx_other_data *data;

	data = (struct wpa_driver_osx_other_data *)priv;
	printf("Realtek:: %s ==>\n", __func__);
	eloop_cancel_timeout(wpa_driver_osx_other_scan_timeout, data, data->ctx);
	eloop_cancel_timeout(wpa_driver_osx_other_assoc_timeout, data, data->ctx);
	SwitchToAPMode(data->connect, 0);
	IOServiceClose(data->connect);
	free(data);
}
int wpa_driver_osx_other_get_capa(void *priv, struct wpa_driver_capa *capa)
{
	memset(capa, 0, sizeof(struct wpa_driver_capa));
	printf("Realtek:: %s ==>\n", __func__);
	capa->key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA |
			WPA_DRIVER_CAPA_KEY_MGMT_WPA2 |
			WPA_DRIVER_CAPA_KEY_MGMT_WPA_PSK |
			WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
	capa->enc = WPA_DRIVER_CAPA_ENC_WEP40 |
			WPA_DRIVER_CAPA_ENC_WEP104 |
			WPA_DRIVER_CAPA_ENC_TKIP |
			WPA_DRIVER_CAPA_ENC_CCMP;
	capa->auth = WPA_DRIVER_AUTH_OPEN |
			WPA_DRIVER_AUTH_SHARED |
			WPA_DRIVER_AUTH_LEAP;
	capa->flags = WPA_DRIVER_FLAGS_AP | WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_8021X;
	printf("Realtek:: %s <==\n", __func__);
	return 0;
}
const u8 * wpa_driver_osx_other_get_mac_addr(void *priv)
{
	struct wpa_driver_osx_other_data *data;

	data = (struct wpa_driver_osx_other_data *)priv;
	printf("Realtek:: %s ==>%X:%X:%X:%X:%X:%X\n",
			__func__,
			data->mac[0],
			data->mac[1],
			data->mac[2],
			data->mac[3],
			data->mac[4],
			data->mac[5]);
	return data->mac;
}

const struct wpa_driver_ops wpa_driver_osx_other_ops = {
	.name = "osx_other",
	.desc = "Realtek MacOSX Wlan driver",
	.get_bssid = wpa_driver_osx_other_get_bssid,
	.get_ssid = wpa_driver_osx_other_get_ssid,
	.set_key = wpa_driver_osx_other_set_key,
	//.set_countermeasures = wpa_driver_wext_set_countermeasures,
	.scan2 = wpa_driver_osx_other_scan,
	.get_scan_results2 = wpa_driver_osx_other_get_scan_results,
	//.deauthenticate = wpa_driver_wext_deauthenticate,
	//.disassociate = wpa_driver_wext_disassociate,
	.associate = wpa_driver_osx_other_associate,
	.init = wpa_driver_osx_other_init,
	.deinit = wpa_driver_osx_other_deinit,
	//.add_pmkid = wpa_driver_wext_add_pmkid,
	//.remove_pmkid = wpa_driver_wext_remove_pmkid,
	//.flush_pmkid = wpa_driver_wext_flush_pmkid,
	.get_capa = wpa_driver_osx_other_get_capa,
	//.set_operstate = wpa_driver_wext_set_operstate,
	//.get_radio_name = wext_get_radio_name,
	.get_mac_addr = wpa_driver_osx_other_get_mac_addr,
};
