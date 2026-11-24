variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Name prefix for all resources"
  type        = string
  default     = "phishing-detector"
}

variable "vpc_cidr" {
  description = "IP range of the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type" {
  description = "EC2 instance size"
  type        = string
  default     = "t3.micro"
}

variable "alert_email" {
  description = "Email that receives CloudWatch alarms"
  type        = string
}