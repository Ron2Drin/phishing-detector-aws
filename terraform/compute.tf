# --- Which OS: latest Amazon Linux 2023 (x86, matches t3.micro) ---
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# --- Where the app logs go in CloudWatch ---
resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/app"
  retention_in_days = 7 # keep logs a week (cost control)
}

# --- The "recipe" for each server ---
resource "aws_launch_template" "app" {
  name_prefix   = "${var.project}-"
  image_id      = data.aws_ami.al2023.id
  instance_type = var.instance_type

  vpc_security_group_ids = [aws_security_group.app.id]

  iam_instance_profile {
    name = aws_iam_instance_profile.app.name
  }

  # Require IMDSv2 (protects the server's temporary credentials)
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tpl", {
    region     = var.region
    bucket     = aws_s3_bucket.code.id
    app_key    = aws_s3_object.app.key
    secret_arn = aws_db_instance.main.master_user_secret[0].secret_arn
    db_host    = aws_db_instance.main.address
    db_name    = aws_db_instance.main.db_name
    log_group  = aws_cloudwatch_log_group.app.name
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project}-app"
    }
  }
}

# --- The Load Balancer (public entry point) ---
resource "aws_lb" "main" {
  name               = "${var.project}-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

# --- The group of servers the ALB sends traffic to + health check ---
resource "aws_lb_target_group" "app" {
  name                 = "${var.project}-tg"
  port                 = 8000
  protocol             = "HTTP"
  vpc_id               = aws_vpc.main.id
  deregistration_delay = 30 # finish in-flight requests before removing a server

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# --- Listen on port 80 and forward to the target group ---
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# --- Keeps 2 servers running, one per AZ, replaces unhealthy ones ---
resource "aws_autoscaling_group" "app" {
  name                = "${var.project}-asg"
  min_size            = 2
  max_size            = 4
  desired_capacity    = 2
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.app.arn]

  health_check_type         = "ELB" # trust the ALB's /health check, not just "is the VM on"
  health_check_grace_period = 300   # give a new server 5 min to install before judging it

  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }

  # When the recipe changes (e.g. new code), replace servers one at a time
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project}-app"
    propagate_at_launch = true
  }
}

output "app_url" {
  value = "http://${aws_lb.main.dns_name}"
}