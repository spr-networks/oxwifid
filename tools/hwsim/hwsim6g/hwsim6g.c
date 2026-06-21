// hwsim6g — clear the NO-IR regulatory flag on the 6 GHz channels of every
// mac80211_hwsim wiphy, so a Rust/hostapd AP can beacon and operate on 6 GHz
// for *interop testing on a signed-regdb kernel* (CONFIG_CFG80211_REQUIRE_
// SIGNED_REGDB=y flags all 6 GHz channels NO-IR for AP mode). hwsim radios are
// virtual, so this only affects the test phys; reversible by reloading hwsim.
//
//   make
//   sudo insmod hwsim6g.ko        # clears NO-IR on all current hwsim 6 GHz chans
//   sudo rmmod hwsim6g            # (or reload mac80211_hwsim to reset)
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/cfg80211.h>

static int __init hwsim6g_init(void)
{
	struct net_device *dev;
	int ifaces = 0;

	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		struct wireless_dev *wdev = dev->ieee80211_ptr;
		struct ieee80211_supported_band *band;
		int i;
		if (!wdev || !wdev->wiphy)
			continue;
		band = wdev->wiphy->bands[NL80211_BAND_6GHZ];
		if (!band)
			continue;
		for (i = 0; i < band->n_channels; i++) {
			band->channels[i].flags &= ~(IEEE80211_CHAN_NO_IR |
				IEEE80211_CHAN_NO_HT40MINUS | IEEE80211_CHAN_NO_HT40PLUS |
				IEEE80211_CHAN_NO_80MHZ | IEEE80211_CHAN_NO_160MHZ);
		}
		ifaces++;
	}
	rtnl_unlock();
	pr_info("hwsim6g: cleared 6GHz NO-IR on %d interfaces\n", ifaces);
	return 0;
}
static void __exit hwsim6g_exit(void) { pr_info("hwsim6g: unloaded\n"); }
module_init(hwsim6g_init);
module_exit(hwsim6g_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("clear NO-IR on hwsim 6GHz channels for interop testing");
