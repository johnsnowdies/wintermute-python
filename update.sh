#!/bin/bash
# Скрипт для копирования единственного JSON-файла с USB-флешки (FAT32)
# в /home/root/.cache/wintermute/profiles с предварительной очисткой старых JSON

set -e  # остановка при любой ошибке

TARGET_DIR="/home/root/.cache/wintermute/profiles"
MOUNT_POINT="/mnt/usb_temp"

# Проверка прав root (нужны для монтирования)
if [[ $EUID -ne 0 ]]; then
   echo "Ошибка: запустите скрипт с sudo: sudo ./copy_config.sh"
   exit 1
fi

# Создаём целевую папку, если её нет
mkdir -p "$TARGET_DIR"

# Создаём временную точку монтирования
mkdir -p "$MOUNT_POINT"

# Ищем все незанятые FAT32-разделы (флешки)
mapfile -t devices < <(lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT -ln | awk '$2=="part" && $3=="vfat" && $4=="" {print "/dev/"$1}')

if [[ ${#devices[@]} -eq 0 ]]; then
    echo "Не найдено ни одной FAT32-флешки без точки монтирования."
    rmdir "$MOUNT_POINT" 2>/dev/null
    exit 1
fi

# Берём первый подходящий раздел
device="${devices[0]}"
echo "Найдена флешка: $device. Монтируем в $MOUNT_POINT"
mount "$device" "$MOUNT_POINT"

# Ищем JSON-файлы в корне флешки
json_files=("$MOUNT_POINT"/*.json)

if [[ ! -f "${json_files[0]}" ]]; then
    echo "На флешке нет ни одного .json файла."
    umount "$MOUNT_POINT"
    rmdir "$MOUNT_POINT"
    exit 1
fi

if [[ ${#json_files[@]} -gt 1 ]]; then
    echo "Ошибка: на флешке несколько .json файлов:"
    printf '  %s\n' "${json_files[@]}"
    echo "Ожидается ровно один. Работа прервана."
    umount "$MOUNT_POINT"
    rmdir "$MOUNT_POINT"
    exit 1
fi

# Копируем
echo "Найден файл: $(basename "${json_files[0]}")"
echo "Удаляем все старые .json в $TARGET_DIR"
rm -f "$TARGET_DIR"/*.json
echo "Копируем новый файл..."
cp "${json_files[0]}" "$TARGET_DIR/"

# Отмонтируем и убираем за собой
umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"

echo "✅ Готово. Файл успешно скопирован."