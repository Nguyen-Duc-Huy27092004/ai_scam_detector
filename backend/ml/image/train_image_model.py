"""
Train image scam detection model (ResNet18).
Run from any CWD: paths are resolved relative to this file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.metrics import classification_report, confusion_matrix
from torch.utils.data import DataLoader
from torchvision import datasets, models, transforms

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data" / "images"

TRAIN_DIR = DATA_DIR / "train"
TEST_DIR = DATA_DIR / "test"

MODEL_DIR = BASE_DIR / "models" / "image_model"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "scam_image_model.pth"
LABELS_PATH = MODEL_DIR / "labels.json"

IMG_SIZE = 224
BATCH_SIZE = 32
EPOCHS = 15
LR = 1e-4

IMAGENET_NORM = transforms.Normalize(
    mean=[0.485, 0.456, 0.406],
    std=[0.229, 0.224, 0.225],
)


def main() -> None:
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Using device:", device)

    train_transform = transforms.Compose(
        [
            transforms.Resize((IMG_SIZE, IMG_SIZE)),
            transforms.RandomHorizontalFlip(),
            transforms.RandomRotation(10),
            transforms.ColorJitter(brightness=0.2, contrast=0.2),
            transforms.ToTensor(),
            IMAGENET_NORM,
        ]
    )

    test_transform = transforms.Compose(
        [
            transforms.Resize((IMG_SIZE, IMG_SIZE)),
            transforms.ToTensor(),
            IMAGENET_NORM,
        ]
    )

    train_dataset = datasets.ImageFolder(str(TRAIN_DIR), transform=train_transform)
    test_dataset = datasets.ImageFolder(str(TEST_DIR), transform=test_transform)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE)

    labels = {str(v): k for k, v in train_dataset.class_to_idx.items()}
    with open(LABELS_PATH, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=4, ensure_ascii=False)

    num_classes = len(labels)

    try:
        weights_enum = models.ResNet18_Weights.DEFAULT
        model = models.resnet18(weights=weights_enum)
    except AttributeError:
        model = models.resnet18(pretrained=True)

    for param in model.parameters():
        param.requires_grad = False

    model.fc = nn.Linear(model.fc.in_features, num_classes)
    model.to(device)

    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.fc.parameters(), lr=LR)

    for epoch in range(EPOCHS):
        model.train()
        total, correct, loss_sum = 0, 0, 0

        for images, targets in train_loader:
            images, targets = images.to(device), targets.to(device)

            optimizer.zero_grad()
            outputs = model(images)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()

            loss_sum += loss.item()
            _, preds = torch.max(outputs, 1)
            total += targets.size(0)
            correct += (preds == targets).sum().item()

        acc = 100 * correct / total
        print(f"Epoch {epoch + 1}/{EPOCHS} | Loss={loss_sum:.4f} | Acc={acc:.2f}%")

    model.eval()
    all_preds, all_labels = [], []

    with torch.no_grad():
        for images, targets in test_loader:
            images, targets = images.to(device), targets.to(device)
            outputs = model(images)
            _, preds = torch.max(outputs, 1)

            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(targets.cpu().numpy())

    print("Confusion Matrix:")
    print(confusion_matrix(all_labels, all_preds))
    print(
        classification_report(
            all_labels, all_preds, target_names=train_dataset.classes
        )
    )

    torch.save(model.state_dict(), MODEL_PATH)
    print("Model saved:", MODEL_PATH)
    print("Labels saved:", LABELS_PATH)


if __name__ == "__main__":
    main()
