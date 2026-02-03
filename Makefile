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
  DEPENDS:=+ucode +libucode +ucode-mod-fs +ucode-mod-ubus +ucode-mod-uci +ucode-mod-math +libmbedtls
endef

define Package/$(PKG_NAME)/description
  A lightweight OIDC/OAuth2 Single Sign-On provider for LuCI with minimal
	dependencies.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/ucode
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ucode/*.so $(1)/usr/lib/ucode/
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
