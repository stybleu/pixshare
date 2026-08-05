# Installation du mode image en attente

1. Publie ces modifications sur GitHub.
2. Sur le service web Render, garde la variable `MODERATION_API_KEY` et ajoute `MODERATION_PENDING_IMAGES=1`.
3. Redéploie PixShare.
4. Envoie une image de test : elle doit apparaître dans ton historique avec « En attente de modération », sans bouton public.
5. Lance `moderation_bot/bot.py` sous Termux avec `DRY_RUN=1`.
6. Quand les décisions te conviennent, passe à `DRY_RUN=0`.

Les images déjà actives avant cette mise à jour restent actives. Seules les nouvelles images passent en attente.
