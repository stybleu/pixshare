# Bot PixShare NudeNet

Le bot ne montre aucune image et ne crée aucun fichier image local. Il récupère les octets par l'API privée, les transmet directement à NudeNet en mémoire, puis approuve ou supprime l'image.

## Test sous Termux

ONNX Runtime et OpenCV doivent venir des paquets Termux :

```bash
pkg update
pkg install python python-numpy python-onnxruntime opencv-python -y
pip install requests
pip install nudenet==3.4.2 --no-deps
```

Vérifie les imports :

```bash
python -c "import onnxruntime, cv2; from nudenet import NudeDetector; print('OK')"
```

Charge les variables sans publier la clé :

```bash
export PIXSHARE_BASE_URL='https://directfile.onrender.com'
export MODERATION_API_KEY='LA_MEME_CLE_QUE_RENDER'
export DRY_RUN=1
export RUN_ONCE=1
python moderation_bot/bot.py
```

En mode `DRY_RUN=1`, les images restent en attente. Les logs n'affichent que l'identifiant, la décision, la classe et le score.

Quand le test est correct :

```bash
export DRY_RUN=0
python moderation_bot/bot.py
```

Les images sûres deviennent publiques. Les images dépassant `BLOCK_THRESHOLD` sont supprimées. Une erreur d'analyse laisse l'image privée et en attente.

## Render

Tu peux créer un **Cron Job** avec :

- Root Directory : `moderation_bot`
- Build Command : `pip install -r requirements.txt`
- Command : `python bot.py`
- Variables : `PIXSHARE_BASE_URL`, `MODERATION_API_KEY`, `DRY_RUN=0`, `RUN_ONCE=1`
- Python : le fichier `.python-version` fixe la branche 3.12 pour éviter les incompatibilités de binaires ML.

Ou un **Background Worker** continu avec `RUN_ONCE=0`.

## Limite importante

NudeNet détecte du contenu explicite probable. Il ne détermine pas qu'un contenu est juridiquement illégal. Commence avec un seuil élevé et teste les faux positifs.
