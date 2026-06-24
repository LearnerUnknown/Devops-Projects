# Devops-Projects

DevOps automation and configuration review tools.

## Projects

| Project | Description |
|---------|-------------|
| [ai-powered-devops-pipeline](ai-projects/ai-powered-devops-pipeline/) | Reviews CI/CD, Docker, Kubernetes, Terraform, Helm, and Ansible configs |

## Clone and run

```bash
git clone https://github.com/LearnerUnknown/Devops-Projects.git
cd Devops-Projects/ai-projects/ai-powered-devops-pipeline
pip install -r requirements.txt
pytest tests/ -v
python app/main.py --path sample-devops-files --output reports/devops-review-report.md
```

## Git commands

```bash
# Pull latest changes
git pull origin main

# Push changes
git add .
git commit -m "Your message"
git push origin main
```
