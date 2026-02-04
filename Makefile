include $(TOPDIR)/rules.mk

PKG_NAME:=luci-sso
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=António Móra <m00qek@gmail.com>
PKG_LICENSE:=MIT

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/$(PKG_NAME)
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=OIDC/OAuth2 SSO for LuCI
  DEPENDS:=+ucode +libucode +ucode-mod-fs +ucode-mod-ubus +ucode-mod-uci +ucode-mod-math +ucode-mod-uclient +luci-sso-crypto
endef

define Package/$(PKG_NAME)/description
  A lightweight OIDC/OAuth2 Single Sign-On provider for LuCI with minimal
	dependencies.
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
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) ./files/www/cgi-bin/luci-sso $(1)/www/cgi-bin/luci-sso
endef

define Package/$(PKG_NAME)-crypto-mbedtls/install
	$(INSTALL_DIR) $(1)/usr/lib/ucode/luci_sso
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ucode/native_mbedtls.so $(1)/usr/lib/ucode/luci_sso/native.so
endef

define Package/$(PKG_NAME)-crypto-wolfssl/install
	$(INSTALL_DIR) $(1)/usr/lib/ucode/luci_sso
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ucode/native_wolfssl.so $(1)/usr/lib/ucode/luci_sso/native.so
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
$(eval $(call BuildPackage,$(PKG_NAME)-crypto-mbedtls))
$(eval $(call BuildPackage,$(PKG_NAME)-crypto-wolfssl))
