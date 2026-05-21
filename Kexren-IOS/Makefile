ARCHS = arm64
DEBUG = 0
FINALPACKAGE = 1
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = ACLunaExternal

# ---- Source list ----------------------------------------------------------
KEXPLOIT_SRC = $(wildcard kexploit/*.m) $(wildcard kexploit/*.c) \
               $(wildcard kexploit/pe/*.m) $(wildcard kexploit/pe/*.c) \
               $(wildcard kexploit/TaskRop/*.m) $(wildcard kexploit/TaskRop/*.c)

ACLunaExternal_FILES = \
    sources/main.m \
    sources/AppDelegate.m \
    sources/ViewController.mm \
    sources/ExternalRead.m \
    sources/ExtGameAPI.m \
    $(KEXPLOIT_SRC)

# ---- Compiler flags -------------------------------------------------------
ACLunaExternal_OBJCCFLAGS = -fobjc-arc
ACLunaExternal_OBJCFLAGS  = -fobjc-arc \
                            -Wno-deprecated-declarations \
                            -Wno-unused-variable -Wno-unused-function -Wno-unused-value \
                            -Wno-pointer-sign -Wno-nonportable-include-path \
                            -Wno-unused-but-set-variable \
                            -Wno-incompatible-pointer-types-discards-qualifiers \
                            -Wno-format \
                            -I./kexploit \
                            -I./kexploit/pe \
                            -I./kexploit/TaskRop \
                            -I./kexploit/choma \
                            -I./kexploit/xpc-stub \
                            -I./Cheat \
                            -include $(PWD)/kexploit/lara_compat.h

# ---- Frameworks + libs ----------------------------------------------------
ACLunaExternal_FRAMEWORKS = UIKit Foundation CoreGraphics QuartzCore
ACLunaExternal_PRIVATE_FRAMEWORKS =

ACLunaExternal_LDFLAGS = -Llibs -lxpf -lgrabkernel2 \
                         -Wl,-rpath,@executable_path/Frameworks

include $(THEOS_MAKE_PATH)/application.mk

# ---- Post-stage: bundle dylibs into Frameworks/ -------------------------
after-stage::
	@echo "[+] Bundling libxpf + libgrabkernel2 into .app/Frameworks/"
	@mkdir -p $(THEOS_STAGING_DIR)/Applications/ACLunaExternal.app/Frameworks
	@cp -f libs/libxpf.dylib         $(THEOS_STAGING_DIR)/Applications/ACLunaExternal.app/Frameworks/ 2>/dev/null || true
	@cp -f libs/libgrabkernel2.dylib $(THEOS_STAGING_DIR)/Applications/ACLunaExternal.app/Frameworks/ 2>/dev/null || true
