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
LOGFILE="$ROOTDIR/build.log"

KIMG_DTB="$OUTDIR/Image.gz-dtb"
KIMG="$OUTDIR/Image.gz"

# ================= TOOLCHAIN =================
TC64="aarch64-linux-gnu-"
TC32="arm-linux-gnueabi-"

# ================= INFO =================
KERNEL_NAME="ReLIFE"
DEVICE="Rolex"

# ================= DATE (WIB) =================
DATE_TITLE=$(TZ=Asia/Jakarta date +"%d%m%Y")
TIME_TITLE=$(TZ=Asia/Jakarta date +"%H%M%S")
BUILD_DATETIME=$(TZ=Asia/Jakarta date +"%d %B %Y")

# ================= TELEGRAM =================
TG_BOT_TOKEN="7443002324:AAFpDcG3_9L0Jhy4v98RCBqu2pGfznBCiDM"
TG_CHAT_ID="-1003520316735"

# ================= CI INFO =================
CI_NUMBER="${GITHUB_RUN_NUMBER:-Manual}"
COMMIT_HASH=$(git rev-parse --short HEAD)
COMMIT_MSG=$(git log -1 --pretty=%s)

# ================= GLOBAL =================
BUILD_TIME="unknown"
KERNEL_VERSION="unknown"
TC_INFO="unknown"
IMG_USED="unknown"
MD5_HASH="unknown"
ZIP_NAME=""

# ================= FUNCTION =================

send_telegram_message() {
    curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TG_CHAT_ID}" \
        -d parse_mode=Markdown \
        -d text="$1"
}

send_telegram_log() {
    curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendDocument" \
        -F chat_id="${TG_CHAT_ID}" \
        -F document=@"${LOGFILE}" \
        -F caption="$1"
}

get_kernel_version() {
    VERSION=$(grep -E '^VERSION =' Makefile | awk '{print $3}')
    PATCHLEVEL=$(grep -E '^PATCHLEVEL =' Makefile | awk '{print $3}')
    SUBLEVEL=$(grep -E '^SUBLEVEL =' Makefile | awk '{print $3}')
    KERNEL_VERSION="${VERSION}.${PATCHLEVEL}.${SUBLEVEL}"
}

build_kernel() {

    echo -e "$yellow[+] Building kernel...$white"

    rm -rf out
    make O=out ARCH=arm64 rolex_defconfig >> $LOGFILE 2>&1 || return 1

    BUILD_START=$(date +%s)

    send_telegram_message "🚀 *CI #${CI_NUMBER} Started*

📱 Device : ${DEVICE}
📝 Commit : ${COMMIT_MSG}
🔗 Hash : \`${COMMIT_HASH}\`"

    make -j$(nproc) O=out ARCH=arm64 \
        CROSS_COMPILE=$TC64 \
        CROSS_COMPILE_ARM32=$TC32 \
        CROSS_COMPILE_COMPAT=$TC32 >> $LOGFILE 2>&1 || return 1

    BUILD_END=$(date +%s)
    DIFF=$((BUILD_END - BUILD_START))
    BUILD_TIME="$((DIFF / 60))m $((DIFF % 60))s"

    get_kernel_version

    ZIP_NAME="${KERNEL_NAME}-${DEVICE}-CI${CI_NUMBER}-${DATE_TITLE}.zip"
}

pack_kernel() {

    git clone https://github.com/rahmatsobrian/AnyKernel3.git "$ANYKERNEL_DIR"

    cd "$ANYKERNEL_DIR" || return 1

    if [ -f "$KIMG_DTB" ]; then
        cp "$KIMG_DTB" Image.gz-dtb
        IMG_USED="Image.gz-dtb"
    elif [ -f "$KIMG" ]; then
        cp "$KIMG" Image.gz
        IMG_USED="Image.gz"
    else
        return 1
    fi

    zip -r9 "$ZIP_NAME" . -x ".git*" "README.md" >> $LOGFILE 2>&1
    MD5_HASH=$(md5sum "$ZIP_NAME" | awk '{print $1}')
}

upload_success() {

    ZIP_PATH="$ANYKERNEL_DIR/$ZIP_NAME"

    curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendDocument" \
        -F chat_id="${TG_CHAT_ID}" \
        -F document=@"${ZIP_PATH}" \
        -F parse_mode=Markdown \
        -F caption="🔥 *CI #${CI_NUMBER} SUCCESS*

📱 Device : ${DEVICE}
📦 Kernel : ${KERNEL_NAME}
🍃 Version : ${KERNEL_VERSION}

📝 Commit :
${COMMIT_MSG}

🔗 Hash : \`${COMMIT_HASH}\`

⌛ Build Time : ${BUILD_TIME}
🔐 MD5 :
\`${MD5_HASH}\`"

    send_telegram_log "📄 Build Log CI #${CI_NUMBER} (SUCCESS)"
}

upload_error() {

    send_telegram_message "❌ *CI #${CI_NUMBER} FAILED*

📱 Device : ${DEVICE}

📝 Commit :
${COMMIT_MSG}

🔗 Hash : \`${COMMIT_HASH}\`

📄 Log dikirim di bawah ⬇️"

    send_telegram_log "📄 Build Log CI #${CI_NUMBER} (FAILED)"
}

# ================= RUN =================

echo "" > $LOGFILE

if build_kernel && pack_kernel; then
    upload_success
else
    upload_error
    exit 1
fi
