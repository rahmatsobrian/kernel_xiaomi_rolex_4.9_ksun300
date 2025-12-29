#!/bin/bash

# ================= COLOR =================
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
white='\033[0m'

# ================= PATH =================
ROOTDIR=$(pwd)
OUTDIR="$ROOTDIR/out/arch/arm64/boot"
ANYKERNEL_DIR="$ROOTDIR/AnyKernel"

KIMG_DTB="$OUTDIR/Image.gz-dtb"
KIMG="$OUTDIR/Image.gz"

# ================= TOOLCHAIN =================
TC64="aarch64-linux-gnu-"
TC32="arm-linux-gnueabi-"

# ================= INFO =================
KERNEL_NAME="ReLIFE"
DEVICE="Rolex"

# ================= DATE =================
DATE_TITLE=$(date +"%d%m%Y")
TIME_TITLE=$(date +"%H%M%S")
DATE_CAPTION=$(date +"%d %B %Y")

# ================= TELEGRAM =================
TG_BOT_TOKEN="7443002324:AAFpDcG3_9L0Jhy4v98RCBqu2pGfznBCiDM"
TG_CHAT_ID="-1003520316735"

# ================= GLOBAL =================
BUILD_TIME="unknown"
KERNEL_VERSION="unknown"
TC_INFO="unknown"
IMG_USED="unknown"
MD5_HASH="unknown"
ZIP_NAME=""

# ================= FUNCTION =================

clone_anykernel() {
    if [ ! -d "$ANYKERNEL_DIR" ]; then
        echo -e "$yellow[+] Cloning AnyKernel3...$white"
        git clone https://github.com/rahmatsobrian/AnyKernel3.git "$ANYKERNEL_DIR" || exit 1
    fi
}

get_toolchain_info() {
    if command -v "${TC64}gcc" >/dev/null 2>&1; then
        GCC_VER=$("${TC64}gcc" -dumpversion)
        TC_INFO="GCC ${GCC_VER}"
    elif command -v gcc >/dev/null 2>&1; then
        GCC_VER=$(gcc -dumpversion)
        TC_INFO="GCC ${GCC_VER}"
    else
        TC_INFO="unknown"
    fi
}

get_kernel_version() {
    if [ -f "out/include/generated/utsrelease.h" ]; then
        KERNEL_VERSION=$(sed -n 's/#define UTS_RELEASE "\(.*\)"/\1/p' \
            out/include/generated/utsrelease.h)
    else
        KERNEL_VERSION="unknown"
    fi
}

send_telegram_error() {
    curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TG_CHAT_ID}" \
        -d parse_mode=Markdown \
        -d text="❌ *Kernel CI Build Failed*"
}

build_kernel() {
curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TG_CHAT_ID}" \
        -d parse_mode=Markdown \
        -d text="🚀 *Kernel CI Build Started...*"
        
    echo -e "$yellow[+] Building kernel...$white"

    rm -rf out
    make O=out ARCH=arm64 rolex_defconfig || {
        send_telegram_error
        exit 1
    }

    get_toolchain_info
    BUILD_START=$(date +%s)

    make -j$(nproc) O=out ARCH=arm64 \
        CROSS_COMPILE=$TC64 \
        CROSS_COMPILE_ARM32=$TC32 \
        CROSS_COMPILE_COMPAT=$TC32 || {
        send_telegram_error
        exit 1
    }

    BUILD_END=$(date +%s)
    DIFF=$((BUILD_END - BUILD_START))
    BUILD_TIME="$((DIFF / 60)) min $((DIFF % 60)) sec"

    get_kernel_version

    ZIP_NAME="${KERNEL_NAME}-${DEVICE}-${KERNEL_VERSION}-${DATE_TITLE}-${TIME_TITLE}.zip"
}

pack_kernel() {
    echo -e "$yellow[+] Packing AnyKernel...$white"

    clone_anykernel
    cd "$ANYKERNEL_DIR" || exit 1

    rm -f Image* *.zip

    if [ -f "$KIMG_DTB" ]; then
        cp "$KIMG_DTB" Image.gz-dtb
        IMG_USED="Image.gz-dtb"
    elif [ -f "$KIMG" ]; then
        cp "$KIMG" Image.gz
        IMG_USED="Image.gz"
    else
        send_telegram_error
        exit 1
    fi

    zip -r9 "$ZIP_NAME" . -x ".git*" "README.md"

    MD5_HASH=$(md5sum "$ZIP_NAME" | awk '{print $1}')

    echo -e "$green[✓] Zip created: $ZIP_NAME ($IMG_USED)$white"
}

upload_telegram() {
    ZIP_PATH="$ANYKERNEL_DIR/$ZIP_NAME"
    [ ! -f "$ZIP_PATH" ] && return

    echo -e "$yellow[+] Uploading to Telegram...$white"

    curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendDocument" \
        -F chat_id="${TG_CHAT_ID}" \
        -F document=@"${ZIP_PATH}" \
        -F parse_mode=Markdown \
        -F caption="🔥 *Kernel CI Build Success*

📱 *Device* : ${DEVICE}
📦 *Kernel Name* : ${KERNEL_NAME}
🍃 *Kernel Version* : ${KERNEL_VERSION}

🛠 *Toolchain* : ${TC_INFO}

⌛ *Build Time* : ${BUILD_TIME}
🕒 *Build Date* : ${DATE_CAPTION}

🔐 *MD5* :
\`${MD5_HASH}\`

✅ *Flash via Recovery*"
}

# ================= RUN =================
START=$(date +%s)

build_kernel
pack_kernel
upload_telegram

END=$(date +%s)
echo -e "$green[✓] Done in $((END - START)) seconds$white"
