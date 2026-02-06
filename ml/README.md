# APEX ML Module

PHP vulnerability detection using Machine Learning.

## Quick Start

```bash
# Scan with pre-trained model
python scan.py target.php
python scan.py ./my_project/
python scan.py --code "<?php echo $_GET['x']; ?>"
```

## Train Your Own Model

```bash
# 1. Download training data
git clone https://github.com/stivalet/PHP-Vulnerability-test-suite data

# 2. Train
python train.py

# 3. Model saved as vuln_model.pkl
```

## Use with APEX

```bash
# From apex root directory
python apex.py target/ --ml-filter php-vuln-ml --ml-model ml/vuln_model.pkl
```

## Model Info

- Algorithm: Random Forest
- Accuracy: 97.5%
- CV Score: 97.1% (+/- 1.9%)
- Classes: SAFE, SQLi, XSS, CMDi, LFI, CODE

## Custom ML Filter

```python
from apex.core.ml_interface import BaseMLFilter, MLFilterRegistry

class MyFilter(BaseMLFilter):
    def load_model(self, path): ...
    def predict(self, finding, code): ...

MLFilterRegistry.register('my-filter', MyFilter)
```
