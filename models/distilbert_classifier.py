"""
models/distilbert_classifier.py — Classifier DistilBERT fine-tuné
Entraînement sur 2657 exemples · ~500MB VRAM · ~10ms/mail inference
"""

import logging
import os
from typing import Optional

import torch

logger = logging.getLogger("distilbert")


class DistilBERTClassifier:
    """
    Charge le modèle DistilBERT fine-tuné pour la détection de phishing.
    Si le modèle n'existe pas localement, utilise le modèle de base.
    """

    def __init__(self):
        from config.settings import Settings
        from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

        cfg = Settings()
        self.max_length = cfg.MODEL_MAX_LENGTH
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"DistilBERT device : {self.device}")

        model_path = cfg.MODEL_PATH
        if os.path.isdir(model_path):
            logger.info(f"Chargement modèle fine-tuné depuis {model_path}")
            self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)
            self.model = DistilBertForSequenceClassification.from_pretrained(model_path)
        else:
            logger.warning("Modèle fine-tuné non trouvé — utilisation modèle de base")
            base = "distilbert-base-uncased"
            self.tokenizer = DistilBertTokenizerFast.from_pretrained(base)
            self.model = DistilBertForSequenceClassification.from_pretrained(
                base, num_labels=2
            )

        self.model.to(self.device)
        self.model.eval()

    def predict(self, mail: dict) -> float:
        """
        Prédit la probabilité que le mail soit du phishing.
        Retourne un score 0–1.
        """
        text = f"{mail.get('subject', '')} {mail.get('body', '')}".strip()
        if not text:
            return 0.0

        try:
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                padding=True,
                max_length=self.max_length,
            ).to(self.device)

            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = torch.softmax(outputs.logits, dim=1)
                phishing_prob = probs[0][1].item()  # label 1 = phishing

            logger.debug(f"DistilBERT uid={mail.get('uid')} score={phishing_prob:.4f}")
            return round(phishing_prob, 4)

        except Exception as e:
            logger.error(f"Erreur DistilBERT inference : {e}")
            return 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  Script d'entraînement
# ══════════════════════════════════════════════════════════════════════════════

class DistilBERTTrainer:
    """
    Fine-tune DistilBERT sur le dataset de 2657 exemples.
    Lance : python distilbert_classifier.py --train data/phishing_dataset.csv
    """

    def train(self, csv_path: str, output_dir: str = "./models/distilbert_phishing"):
        import csv
        from torch.utils.data import Dataset, DataLoader
        from transformers import (
            DistilBertTokenizerFast,
            DistilBertForSequenceClassification,
            AdamW,
            get_linear_schedule_with_warmup,
        )
        from sklearn.model_selection import train_test_split

        logger.info(f"Chargement dataset : {csv_path}")

        # ── Chargement données ───────────────────────────────────────────
        texts, labels = [], []
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                text = row.get("text", row.get("body", ""))
                label = int(row.get("label", 0))
                if text:
                    texts.append(text)
                    labels.append(label)

        logger.info(f"{len(texts)} exemples chargés ({sum(labels)} phishing, {len(labels)-sum(labels)} légitimes)")

        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts, labels, test_size=0.15, random_state=42, stratify=labels
        )

        # ── Dataset ──────────────────────────────────────────────────────
        tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

        class PhishingDataset(Dataset):
            def __init__(self, texts, labels, tokenizer, max_len=512):
                self.encodings = tokenizer(
                    texts, truncation=True, padding=True, max_length=max_len
                )
                self.labels = labels

            def __len__(self):
                return len(self.labels)

            def __getitem__(self, idx):
                item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
                item["labels"] = torch.tensor(self.labels[idx])
                return item

        train_dataset = PhishingDataset(train_texts, train_labels, tokenizer)
        val_dataset = PhishingDataset(val_texts, val_labels, tokenizer)

        train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=32)

        # ── Modèle ───────────────────────────────────────────────────────
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = DistilBertForSequenceClassification.from_pretrained(
            "distilbert-base-uncased", num_labels=2
        ).to(device)

        optimizer = AdamW(model.parameters(), lr=2e-5)
        total_steps = len(train_loader) * 3
        scheduler = get_linear_schedule_with_warmup(
            optimizer, num_warmup_steps=total_steps // 10, num_training_steps=total_steps
        )

        # ── Training loop ─────────────────────────────────────────────────
        for epoch in range(3):
            model.train()
            total_loss = 0
            for batch in train_loader:
                batch = {k: v.to(device) for k, v in batch.items()}
                outputs = model(**batch)
                loss = outputs.loss
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()
                total_loss += loss.item()

            avg_loss = total_loss / len(train_loader)

            # Validation
            model.eval()
            correct, total = 0, 0
            with torch.no_grad():
                for batch in val_loader:
                    batch = {k: v.to(device) for k, v in batch.items()}
                    outputs = model(**batch)
                    preds = torch.argmax(outputs.logits, dim=1)
                    correct += (preds == batch["labels"]).sum().item()
                    total += len(batch["labels"])

            acc = correct / total
            logger.info(f"Epoch {epoch+1}/3 — loss={avg_loss:.4f} val_acc={acc:.4f}")

        # ── Sauvegarde ───────────────────────────────────────────────────
        os.makedirs(output_dir, exist_ok=True)
        model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)
        logger.info(f"Modèle sauvegardé → {output_dir}")


if __name__ == "__main__":
    import sys
    if "--train" in sys.argv:
        idx = sys.argv.index("--train")
        csv_path = sys.argv[idx + 1]
        trainer = DistilBERTTrainer()
        trainer.train(csv_path)
    else:
        print("Usage: python distilbert_classifier.py --train <dataset.csv>")
