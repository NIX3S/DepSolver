<div align="center">

# 🧩 depsolver

### Résolveur de dépendances Python orienté sécurité, compatibilité API réelle et maintenabilité.

*L’outil ne se contente pas de vérifier les contraintes de version : il cherche une version commune qui soit à la fois compatible, récente et exempte de vulnérabilités critiques.*

---

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![CLI](https://img.shields.io/badge/CLI-typer-4B8BBE.svg)
![SQLite](https://img.shields.io/badge/API-Compatibility-009688.svg)
![Security](https://img.shields.io/badge/CVE-OSV-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

</div>

---

# 📖 Présentation

**depsolver** est un résolveur de dépendances Python conçu pour aller au-delà des simples contraintes de version.

Son objectif est simple : trouver automatiquement une version **sûre**, **récente** et **réellement compatible** entre plusieurs dépendants, en tenant compte de trois dimensions à la fois :

- les contraintes de version classiques ;
- la compatibilité API effective, via l’analyse des appels réellement utilisés ;
- les vulnérabilités connues, via les politiques CVE.

L’outil peut ainsi détecter non seulement qu’une version “matche” sur le papier, mais aussi qu’elle reste utilisable en pratique sans breaking change sur les symboles effectivement appelés par le code.

---

# ✨ Pourquoi depsolver ?

Dans beaucoup de projets Python, la résolution se limite à :

- choisir une version qui satisfait les bornes `>=`, `<`, `==` ;
- espérer que l’API n’a pas cassé ;
- vérifier la sécurité à la main, parfois après coup.

depsolver change cette approche.

Il cherche une **version point de rencontre** qui :

- satisfait plusieurs dépendants simultanément ;
- évite les versions vulnérables selon une politique configurable ;
- vérifie la compatibilité réelle des appels API ;
- documente clairement pourquoi une version a été retenue ou rejetée.

L’outil est pensé pour les environnements où la fiabilité de la chaîne de dépendances compte autant que la rapidité de résolution.

---

# 🌟 Fonctionnalités

## 🔍 Résolution intelligente

depsolver peut partir de zéro ou auditer un environnement existant.

Il sait :

- résoudre un ensemble de `--require` ;
- vérifier un `requirements.txt` déjà figé ;
- comparer deux environnements ;
- analyser un projet local ou un dépôt distant ;
- produire une version alternative meilleure si la version actuelle pose problème.

---

## 🧠 Vérification de compatibilité API

Au lieu de se contenter de la version majeure ou des métadonnées déclaratives, depsolver vérifie les symboles réellement utilisés par le code.

Il peut ainsi détecter :

- les changements de signature ;
- les symboles renommés ou supprimés ;
- les incompatibilités réelles entre code et dépendance ;
- les cas où une version ancienne et une version récente restent toutes deux valides, car l’API utilisée n’a pas changé.

---

## 🛡️ Politique de sécurité CVE

Le résolveur interroge les vulnérabilités connues pour chaque version candidate et applique une politique de sécurité.

Politiques supportées :

- `cve-none`
- `cve-no-critical`
- `cve-custom`

En dernier recours, le moteur peut dégrader la politique de façon minimale pour trouver une solution, tout en l’annonçant clairement dans le rapport.

---

## 📦 Analyse de projet

depsolver peut auditer un projet local ou un dépôt Git.

Il est capable de :

- parser `requirements.txt` et `pyproject.toml` ;
- cloner et mettre en cache un dépôt distant ;
- exécuter des tests dans un environnement isolé ;
- produire un rapport détaillé ;
- exporter un lock file ;
- générer un graphe de dépendances ;
- expliquer pourquoi un paquet est retenu ou bloqué.

---

## 📄 Rapports détaillés

L’outil peut générer plusieurs formes de sortie :

- texte ;
- JSON ;
- HTML ;
- lock file ;
- graphe Graphviz.

Le rapport HTML présente les résultats de façon lisible, avec des sections repliables, un ordre décroissant des versions et une distinction claire entre :

- **solution retenue** ;
- **versions bloquées** ;
- **sous-dépendances** ;
- **paquets non vérifiés** ;
- **versions écartées pour CVE** ;
- **versions écartées pour breaking change**.

---

# 🏗️ Architecture générale

Le projet est organisé autour d’un cœur de résolution autonome, sans déléguer le problème à pip ou à Poetry.

```text
Utilisateur
   │
   ├── CLI
   ├── Projet local
   ├── Requirements
   └── Dépôt Git
   ▼
depsolver
   │
   ├── Parser
   ├── Resolver par backtracking
   ├── Analyseur d’API
   ├── Client PyPI
   ├── Client OSV
   ├── Optimiseur
   ├── Exécuteur de tests
   └── Générateur de rapports
```

L’idée centrale est de séparer clairement :

- la découverte des versions ;
- la vérification de compatibilité ;
- l’analyse de sécurité ;
- la production du résultat final.

---

# 📁 Structure du projet

```text
depsolver/
├── cli.py
├── resolver.py
├── optimizer.py
├── versions.py
├── cve.py
├── api_analyzer.py
├── project.py
├── git_integration.py
├── tests_runner.py
├── report.py
└── ...
```

Le dépôt contient également la spécification complète dans :

```text
../depsolver-specification.md
```

Ce document décrit l’architecture, l’algorithme et les exemples de CLI.

---

# ⚙️ Installation

```bash
pip install -e .
```

Pour le développement :

```bash
pip install -e ".[dev]"
```

ou simplement :

```bash
pip install pytest
```

---

# 🚀 Utilisation

## Résoudre à partir de zéro

```bash
depsolver solve --require "libA>=1.0" --require "libB" --require "libC" \
  --analyze-api --policy cve-no-critical --output requirements.txt --json
```

Cette commande cherche une version compatible pour l’ensemble des contraintes, en appliquant l’analyse API et la politique CVE choisie.

---

## Vérifier un requirements existant

```bash
depsolver solve --input requirements.txt --check-only --analyze-api --json
```

Le pin exact est réellement vérifié, mais depsolver calcule quand même la meilleure alternative possible et l’écrit dans sa sortie dédiée.

---

## Auditer un projet local

```bash
depsolver check --path /chemin/vers/projet --analyze-api \
  --tests "pytest tests/" --html rapport.html --lock requirements.lock \
  --graphviz deps.dot --explain libC
```

Cette commande analyse le projet, exécute les tests si demandé, produit un rapport HTML et peut exporter un graphe exploitable avec Graphviz.

---

## Auditer un dépôt distant

```bash
depsolver check --repo https://github.com/user/project --branch main \
  --analyze-api --tests "pytest tests/" --best-output best.txt
```

Le dépôt est cloné localement, mis en cache, puis réutilisé lors des exécutions suivantes.

---

## Comparer deux environnements

```bash
depsolver compare --env1 prod.txt --env2 staging.txt --name1 prod --name2 staging --html diff.html
```

Cette commande permet d’identifier rapidement les différences entre deux environnements Python.

---

# 🔎 Transparence des résultats

depsolver distingue explicitement les cas suivants :

- **verified: true** : la compatibilité API a bien été confirmée ;
- **verified: false** : la compatibilité n’a pas pu être confirmée, mais la version reste candidate selon les contraintes et les CVE ;
- **blocked** : la version a été rejetée à cause d’une incompatibilité réelle ou d’une vulnérabilité ;
- **best alternative** : la meilleure version disponible, même si la version figée n’est pas acceptable.

Cette transparence est importante : l’outil ne masque pas les cas incomplets, il les signale clairement.

---

# 🧠 Analyse API

L’analyse API repose sur l’extraction des appels réellement effectués dans le code.

Elle permet notamment de :

- repérer les fonctions et méthodes réellement utilisées ;
- vérifier les signatures après installation isolée de chaque version candidate ;
- rejeter précisément une version cassée ;
- accepter deux versions éloignées si les symboles utilisés sont restés compatibles ;
- éviter de confondre “ancienne version” et “API cassée”.

L’analyse est volontairement ciblée sur les symboles effectivement appelés, pour rester pertinente et éviter les faux positifs.

---

# 🛡️ Gestion des CVE

Chaque version candidate est évaluée selon la politique de sécurité choisie.

Le moteur peut :

- interroger OSV ;
- écarter les versions critiques ;
- conserver les versions acceptables selon la politique demandée ;
- dégrader la politique de façon minimale si aucune solution n’est trouvée ;
- signaler clairement les décisions dans les sorties texte, JSON et HTML.

---

# 📊 Fenêtre de versions

Par défaut, depsolver ne scanne pas tout l’historique d’un paquet.

Il commence par une fenêtre courte sur les versions les plus récentes, puis élargit automatiquement si nécessaire.

Ce comportement permet :

- de garder de bonnes performances ;
- d’éviter les rétrogradations inutiles ;
- de privilégier les versions récentes compatibles ;
- de rester prévisible même avec des pins exacts.

Avec `--exact-pins`, un pin `==` redevient un verrou strict.

---

# 🧪 Tests

```bash
pytest tests/ -v
```

La suite de tests couvre notamment :

- la résolution de dépendances ;
- l’analyse API ;
- les symboles imbriqués ;
- les cas de backtracking ;
- la détection des versions cassées ;
- la stratégie de fenêtre de versions ;
- les cas de pin exact et de `--exact-pins`.

---

# 🧰 Exemples de sortie

## Solution retenue

Le rapport final indique :

- la version choisie ;
- les versions rejetées ;
- la raison du rejet ;
- l’état de vérification API ;
- la politique CVE appliquée ;
- les sous-dépendances associées.

## Version bloquée

Lorsqu’une version plus récente casserait quelque chose, depsolver peut expliquer précisément :

- quel symbole pose problème ;
- quel paramètre a changé ;
- si le blocage vient d’une CVE ;
- si la version est simplement non vérifiée.

---

# 🔧 Fonctionnement interne

Le pipeline global s’articule autour de plusieurs étapes :

1. lecture des contraintes ;
2. récupération des versions disponibles ;
3. filtrage par politique CVE ;
4. vérification de la compatibilité API ;
5. backtracking sur les contraintes transitives ;
6. sélection de la meilleure version commune ;
7. génération des sorties texte, JSON, HTML ou lock.

Cette architecture permet de combiner sécurité, exactitude et traçabilité.

---

# 🛣️ Roadmap

- [x] Parsing `requirements.txt`
- [x] Parsing `pyproject.toml`
- [x] Resolver par backtracking
- [x] Analyse API par version
- [x] Vérification CVE via OSV
- [x] CLI complète
- [x] Rapports JSON / HTML
- [x] Comparaison d’environnements
- [x] Graphe de dépendances
- [ ] Création automatique de branche / commit après `check --apply`
- [ ] Politique `cve-custom` entièrement configurable via fichier
- [ ] Amélioration de l’analyse AST avec inférence de type légère
- [ ] Support enrichi des dépendances non standards

---

# ⚠️ Notes et limites

- L’analyse AST reste volontairement conservatrice.
- Certains appels dynamiques peuvent ne pas être détectés.
- Un paquet peut être marqué “non vérifié” si l’installation isolée de sa version échoue.
- L’accès réseau est nécessaire pour PyPI et OSV dans un environnement réel.
- Graphviz doit être installé côté utilisateur pour le rendu PNG des fichiers `.dot`.

---

# 🤝 Contribution

Les contributions sont les bienvenues.

Avant une Pull Request :

- créer une branche dédiée ;
- garder la séparation nette entre résolution, analyse et reporting ;
- ajouter des tests pour chaque nouveau comportement ;
- documenter les changements de CLI ou de politique de résolution.

---

# 📄 Licence

Ce projet est distribué sous licence **MIT**.

---

# ❤️ À propos

**depsolver** est né d’un besoin simple : rendre la résolution de dépendances Python plus fiable, plus transparente et plus utile en pratique.

L’objectif n’est pas seulement de trouver une version qui “passe”, mais de trouver celle qui reste compatible, maintenable et défendable dans le temps.

<div align="center">

## ⭐ Si ce projet vous plaît, n’hésitez pas à lui attribuer une étoile sur GitHub !

**Bon usage de depsolver !**

</div>