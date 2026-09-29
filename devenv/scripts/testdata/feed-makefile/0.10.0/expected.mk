include $(TOPDIR)/rules.mk

PKG_NAME:=luci-sso
PKG_VERSION:=0.10.0
PKG_RELEASE:=1

PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/m00qek/luci-sso/archive/refs/tags/
PKG_HASH:=c8b77f7fad42492e6b13a0f6e1c9b64f76d2c8396811aabc7f311ce47bcaeceb
PKG_BUILD_DIR:=$(BUILD_DIR)/luci-sso-$(PKG_VERSION)

PKG_MAINTAINER:=António Móra <m00qek@gmail.com>
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_INSTALL:=1
PKG_BUILD_DEPENDS:=libucode/host
PKG_DEPENDS:=+ucode +libucode +ucode-mod-fs +ucode-mod-ubus +ucode-mod-uci +ucode-mod-math +ucode-mod-uclient +ucode-mod-uloop +ucode-mod-log +liblucihttp-ucode +rpcd-mod-ucode

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=OIDC/OAuth2 SSO for LuCI
  URL:=https://github.com/m00qek/luci-sso
  DEPENDS:=$(PKG_DEPENDS) +luci-sso-crypto +luci-base
endef

define Package/$(PKG_NAME)/description
  A lightweight OIDC/OAuth2 Single Sign-On provider for LuCI with minimal dependencies.
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/luci-sso
endef

define Package/$(PKG_NAME)-crypto-mbedtls
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=MbedTLS backend for $(PKG_NAME)
  URL:=https://github.com/m00qek/luci-sso
  DEPENDS:=+libucode +libmbedtls
  PROVIDES:=luci-sso-crypto
endef

define Package/$(PKG_NAME)-crypto-wolfssl
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=WolfSSL backend for $(PKG_NAME)
  URL:=https://github.com/m00qek/luci-sso
  DEPENDS:=+libucode +libwolfssl
  PROVIDES:=luci-sso-crypto
endef

define Package/$(PKG_NAME)-crypto-openssl
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=OpenSSL backend for $(PKG_NAME)
  URL:=https://github.com/m00qek/luci-sso
  DEPENDS:=+libucode +libopenssl
  PROVIDES:=luci-sso-crypto
endef

# The release tarball keeps the C sources under mod/, but cmake.mk expects
# CMakeLists.txt at the root of PKG_BUILD_DIR. Unpack normally, then lift mod/
# up one level — the in-tree Makefile copies ./mod/* for the same reason.
define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) $(PKG_BUILD_DIR)/mod/. $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/share/ucode
	$(CP) $(PKG_BUILD_DIR)/src/luci_sso $(1)/usr/share/ucode/
	$(INSTALL_DIR) $(1)/etc/config
	$(CP) $(PKG_BUILD_DIR)/files/etc/config/luci-sso $(1)/etc/config/luci-sso
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/uci-defaults/10-luci-sso-setup $(1)/etc/uci-defaults/10-luci-sso-setup
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/uci-defaults/20-luci-sso-rpcd $(1)/etc/uci-defaults/20-luci-sso-rpcd
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/uci-defaults/99-luci-sso-ui $(1)/etc/uci-defaults/99-luci-sso-ui
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/usr/sbin/luci-sso-cleanup $(1)/usr/sbin/luci-sso-cleanup
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/usr/sbin/luci-sso-repatch $(1)/usr/sbin/luci-sso-repatch
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/www/cgi-bin/luci-sso $(1)/www/cgi-bin/luci-sso
	$(INSTALL_DIR) $(1)/www/luci-static/resources
	$(CP) $(PKG_BUILD_DIR)/files/www/luci-static/resources/luci-sso-login.js $(1)/www/luci-static/resources/
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/services
	$(CP) $(PKG_BUILD_DIR)/files/www/luci-static/resources/view/services/sso.js $(1)/www/luci-static/resources/view/services/
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(CP) $(PKG_BUILD_DIR)/files/usr/share/luci/menu.d/luci-app-sso.json $(1)/usr/share/luci/menu.d/
	$(CP) $(PKG_BUILD_DIR)/files/usr/share/luci/menu.d/luci-sso-logout.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DIR) $(1)/usr/share/ucode/luci/controller
	$(CP) $(PKG_BUILD_DIR)/files/usr/share/ucode/luci/controller/sso.uc $(1)/usr/share/ucode/luci/controller/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(CP) $(PKG_BUILD_DIR)/files/usr/share/rpcd/acl.d/luci-app-sso.json $(1)/usr/share/rpcd/acl.d/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(CP) $(PKG_BUILD_DIR)/files/usr/share/rpcd/ucode/luci-sso.uc $(1)/usr/share/rpcd/ucode/
endef

define Package/$(PKG_NAME)/prerm
#!/bin/sh
# Shell variables are written $$name: this block is expanded by make first.

# Clean up cron job
sed -i '/luci-sso-cleanup/d' /etc/crontabs/root 2>/dev/null
[ -x "/etc/init.d/cron" ] && /etc/init.d/cron restart

# Remove the login button from every LuCI login template. An upgrade puts it
# back: the new package's uci-defaults script runs luci-sso-repatch again.
[ -x /usr/sbin/luci-sso-repatch ] && /usr/sbin/luci-sso-repatch --remove >/dev/null 2>&1

# Real removal only: take away everything luci-sso gave rpcd, and keep the
# roles' permissions. luci_sso.rpcd_login.demigrate() copies each SSO role's
# login entry (luci_sso_<role>) back onto its role in /etc/config/luci-sso as
# the read/write lists earlier releases used, and deletes the entries; the
# commit to luci-sso comes first, so an interruption loses nothing. A later
# install moves the lists back into rpcd (uci-defaults 20-luci-sso-rpcd), with
# the same entries. The settings ACL and the luci-sso ubus object are deleted
# too, before the package manager removes the rest. Then rpcd reloads: it
# re-executes itself and rebuilds each session's rights from /etc/config/rpcd
# and the ACL files left, so password logins stay logged in without the SSO
# settings ACL, and SSO sessions, whose entries are gone, keep no rights at
# all. An upgrade or downgrade keeps all of this, so it skips it: opkg exports
# PKG_UPGRADE=1 then, and apk does not run this script on upgrade at all. opkg
# --force-reinstall looks like a removal (PKG_UPGRADE=0), so it goes through
# here, and the new package's uci-defaults script recreates every entry.
if [ "$${PKG_UPGRADE:-0}" != "1" ]; then
	# A private delta directory, so the commits write only these changes,
	# never changes to rpcd or luci-sso someone else staged in /tmp/.uci.
	d=$$(mktemp -d)
	LUCI_SSO_DELTA="$$d" ucode -e '
import { cursor } from "uci";
import { demigrate } from "luci_sso.rpcd_login";

let uci = cursor("/etc/config", getenv("LUCI_SSO_DELTA"));
let changed = demigrate(uci, (msg) => print(msg, "\n"));
if (changed.luci_sso && !uci.commit("luci-sso"))
	die("could not write /etc/config/luci-sso: the rpcd login entries are kept");
if (changed.rpcd)
	uci.commit("rpcd");
' 2>&1 | while read -r line; do
		logger -t luci-sso -p user.warn "$$line"
		echo "luci-sso: $$line" >&2
	done
	rm -rf "$$d"
	rm -f /usr/share/rpcd/acl.d/luci-app-sso.json /usr/share/rpcd/ucode/luci-sso.uc 2>/dev/null
	[ -x "/etc/init.d/rpcd" ] && /etc/init.d/rpcd reload >/dev/null 2>&1 || true
fi

# Clear LuCI cache to reflect removal
rm -rf /tmp/luci-modulecache/* 2>/dev/null
rm -rf /tmp/luci-indexcache* 2>/dev/null

exit 0
endef

define Package/$(PKG_NAME)-crypto-mbedtls/install
	$(INSTALL_DIR) $(1)/usr/lib/ucode/luci_sso
	[ -f $(PKG_INSTALL_DIR)/usr/lib/ucode/native_mbedtls.so ] && \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/ucode/native_mbedtls.so $(1)/usr/lib/ucode/luci_sso/native.so || true
endef

define Package/$(PKG_NAME)-crypto-wolfssl/install
	$(INSTALL_DIR) $(1)/usr/lib/ucode/luci_sso
	[ -f $(PKG_INSTALL_DIR)/usr/lib/ucode/native_wolfssl.so ] && \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/ucode/native_wolfssl.so $(1)/usr/lib/ucode/luci_sso/native.so || true
endef

define Package/$(PKG_NAME)-crypto-openssl/install
	$(INSTALL_DIR) $(1)/usr/lib/ucode/luci_sso
	[ -f $(PKG_INSTALL_DIR)/usr/lib/ucode/native_openssl.so ] && \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/ucode/native_openssl.so $(1)/usr/lib/ucode/luci_sso/native.so || true
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
$(eval $(call BuildPackage,$(PKG_NAME)-crypto-mbedtls))
$(eval $(call BuildPackage,$(PKG_NAME)-crypto-wolfssl))
$(eval $(call BuildPackage,$(PKG_NAME)-crypto-openssl))
