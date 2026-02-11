include $(TOPDIR)/rules.mk

PKG_NAME:=luci-sso
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=António Móra <m00qek@gmail.com>
PKG_LICENSE:=MIT

PKG_INSTALL:=1
PKG_DEPENDS:=+ucode +libucode +ucode-mod-fs +ucode-mod-ubus +ucode-mod-uci +ucode-mod-math +ucode-mod-uclient +ucode-mod-uloop +ucode-mod-log +liblucihttp-ucode

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=OIDC/OAuth2 SSO for LuCI
  DEPENDS:=$(PKG_DEPENDS) +luci-sso-crypto
endef

define Package/$(PKG_NAME)/description
  A lightweight OIDC/OAuth2 Single Sign-On provider for LuCI with minimal
	dependencies.
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/luci-sso
endef

define Package/$(PKG_NAME)-crypto-mbedtls
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=MbedTLS backend for $(PKG_NAME)
  DEPENDS:=+libucode +libmbedtls
  PROVIDES:=luci-sso-crypto
endef

define Package/$(PKG_NAME)-crypto-wolfssl
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=WolfSSL backend for $(PKG_NAME)
  DEPENDS:=+libucode +libwolfssl
  PROVIDES:=luci-sso-crypto
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/share/ucode/luci_sso
	$(CP) ./files/usr/share/ucode/luci_sso/*.uc $(1)/usr/share/ucode/luci_sso/
	$(INSTALL_DIR) $(1)/etc/config
	$(CP) ./files/etc/config/luci-sso $(1)/etc/config/luci-sso
	$(INSTALL_DIR) $(1)/etc/luci-sso
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/10-luci-sso-setup $(1)/etc/uci-defaults/10-luci-sso-setup
	$(INSTALL_BIN) ./files/etc/uci-defaults/99-luci-sso-ui $(1)/etc/uci-defaults/99-luci-sso-ui
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/luci-sso-cleanup $(1)/usr/sbin/luci-sso-cleanup
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) ./files/www/cgi-bin/luci-sso $(1)/www/cgi-bin/luci-sso
	$(INSTALL_DIR) $(1)/www/luci-static/resources
	$(CP) ./files/www/luci-static/resources/luci-sso-login.js $(1)/www/luci-static/resources/
endef

define Package/$(PKG_NAME)/prerm
#!/bin/sh
# Clean up cron job
sed -i '/luci-sso-cleanup/d' /etc/crontabs/root 2>/dev/null
[ -x "/etc/init.d/cron" ] && /etc/init.d/cron restart

# Revert UI patches
sed -i '/luci-sso-login.js/d' /usr/share/ucode/luci/template/sysauth.ut 2>/dev/null
sed -i '/luci-sso-login.js/d' /usr/share/ucode/luci/template/themes/bootstrap/sysauth.ut 2>/dev/null

# Clear LuCI cache to reflect removal
rm -rf /tmp/luci-modulecache/* 2>/dev/null
rm -rf /tmp/luci-indexcache 2>/dev/null

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

$(eval $(call BuildPackage,$(PKG_NAME)))
$(eval $(call BuildPackage,$(PKG_NAME)-crypto-mbedtls))
$(eval $(call BuildPackage,$(PKG_NAME)-crypto-wolfssl))
