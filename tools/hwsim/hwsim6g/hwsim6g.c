// hwsim6g — clear the regulatory restrictions that block AP beaconing on every
// mac80211_hwsim wiphy, so a Rust/reference AP AP can operate on 6 GHz *and* on wide
// (80/160 MHz) 5 GHz channels — including DFS radar blocks — for *interop
// testing on a signed-regdb kernel*:
//
//   * 6 GHz: CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=y flags all 6 GHz channels
//     NO-IR for AP mode.
//   * 5 GHz 160 MHz: every 5 GHz 160 MHz block (e.g. 36..64) spans DFS radar
//     channels (52..64), which the kernel refuses to beacon on without a
//     Channel Availability Check. Clearing RADAR/NO-IR (and marking the DFS
//     state AVAILABLE) makes hwsim treat them as ordinary channels.
//
// hwsim radios are virtual, so this only affects the test phys; reversible by
// reloading mac80211_hwsim.
//
//   make
//   sudo insmod hwsim6g.ko        # after `iw reg set US`, before starting the AP
//   sudo rmmod  hwsim6g           # (or reload mac80211_hwsim to reset)
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/cfg80211.h>

static void hwsim6g_clear_band(struct ieee80211_supported_band *band)
{
	int i;

	if (!band)
		return;
	for (i = 0; i < band->n_channels; i++) {
		band->channels[i].flags &= ~(IEEE80211_CHAN_NO_IR |
			IEEE80211_CHAN_RADAR |
			IEEE80211_CHAN_NO_HT40MINUS | IEEE80211_CHAN_NO_HT40PLUS |
			IEEE80211_CHAN_NO_80MHZ | IEEE80211_CHAN_NO_160MHZ);
		/* A radar channel must be marked CAC-complete to beacon on it. */
		band->channels[i].dfs_state = NL80211_DFS_AVAILABLE;
	}
}

static int __init hwsim6g_init(void)
{
	struct net_device *dev;
	int ifaces = 0;

	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		struct wireless_dev *wdev = dev->ieee80211_ptr;
		if (!wdev || !wdev->wiphy)
			continue;
		hwsim6g_clear_band(wdev->wiphy->bands[NL80211_BAND_5GHZ]);
		hwsim6g_clear_band(wdev->wiphy->bands[NL80211_BAND_6GHZ]);
		ifaces++;
	}
	rtnl_unlock();
	pr_info("hwsim6g: cleared NO-IR/RADAR/width caps on 5+6 GHz of %d interfaces\n", ifaces);
	return 0;
}
static void __exit hwsim6g_exit(void) { pr_info("hwsim6g: unloaded\n"); }
module_init(hwsim6g_init);
module_exit(hwsim6g_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("clear NO-IR/RADAR/width caps on hwsim 5+6 GHz channels for interop testing");
