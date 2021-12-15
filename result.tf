resource "google_project" "web_size_architecture" {
  auto_create_network = true
  billing_account     = "018DD6-35B734-4076AE"
  name                = "Web Project"
  project_id          = "web-size-architecture"
}
# terraform import google_project.web_size_architecture projects/web-size-architecture
resource "google_compute_disk" "backend_mig_1b89" {
  image                     = "https://www.googleapis.com/compute/beta/projects/debian-cloud/global/images/debian-10-buster-v20211209"
  name                      = "backend-mig-1b89"
  physical_block_size_bytes = 4096
  project                   = "web-size-architecture"
  size                      = 10
  type                      = "pd-standard"
  zone                      = "europe-west1-b"
}
# terraform import google_compute_disk.backend_mig_1b89 projects/web-size-architecture/zones/europe-west1-b/disks/backend-mig-1b89
resource "google_compute_backend_service" "frontend_bs" {
  health_checks         = ["https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/healthChecks/frontend-check"]
  load_balancing_scheme = "EXTERNAL"
  name                  = "frontend-bs"
  port_name             = "http"
  project               = "web-size-architecture"
  protocol              = "HTTP"
  session_affinity      = "NONE"
  timeout_sec           = 30
}
# terraform import google_compute_backend_service.frontend_bs projects/web-size-architecture/global/backendServices/frontend-bs
resource "google_compute_disk" "frontend_mig_4cqc" {
  image                     = "https://www.googleapis.com/compute/beta/projects/centos-cloud/global/images/centos-7-v20211214"
  name                      = "frontend-mig-4cqc"
  physical_block_size_bytes = 4096
  project                   = "web-size-architecture"
  size                      = 20
  type                      = "pd-standard"
  zone                      = "europe-west1-b"
}
# terraform import google_compute_disk.frontend_mig_4cqc projects/web-size-architecture/zones/europe-west1-b/disks/frontend-mig-4cqc
resource "google_compute_disk" "backend_mig_vvpt" {
  image                     = "https://www.googleapis.com/compute/beta/projects/debian-cloud/global/images/debian-10-buster-v20211209"
  name                      = "backend-mig-vvpt"
  physical_block_size_bytes = 4096
  project                   = "web-size-architecture"
  size                      = 10
  type                      = "pd-standard"
  zone                      = "europe-west1-c"
}
# terraform import google_compute_disk.backend_mig_vvpt projects/web-size-architecture/zones/europe-west1-c/disks/backend-mig-vvpt
resource "google_compute_firewall" "allow_http_three_tier" {
  allow {
    ports    = ["80"]
    protocol = "tcp"
  }
  direction     = "INGRESS"
  name          = "allow-http-three-tier"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  priority      = 1000
  project       = "web-size-architecture"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["allow-http"]
}
# terraform import google_compute_firewall.allow_http_three_tier projects/web-size-architecture/global/firewalls/allow-http-three-tier
resource "google_compute_firewall" "allow_internal_private" {
  allow {
    ports    = ["1-65535"]
    protocol = "tcp"
  }
  allow {
    ports    = ["1-65535"]
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }
  direction     = "INGRESS"
  name          = "allow-internal-private"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  priority      = 65534
  project       = "web-size-architecture"
  source_ranges = ["10.0.1.0/24", "10.0.2.0/24"]
}
# terraform import google_compute_firewall.allow_internal_private projects/web-size-architecture/global/firewalls/allow-internal-private
resource "google_compute_disk" "frontend_mig_gmdc" {
  image                     = "https://www.googleapis.com/compute/beta/projects/centos-cloud/global/images/centos-7-v20211214"
  name                      = "frontend-mig-gmdc"
  physical_block_size_bytes = 4096
  project                   = "web-size-architecture"
  size                      = 20
  type                      = "pd-standard"
  zone                      = "europe-west1-c"
}
# terraform import google_compute_disk.frontend_mig_gmdc projects/web-size-architecture/zones/europe-west1-c/disks/frontend-mig-gmdc
resource "google_compute_firewall" "allow_lb_health_three_tier" {
  allow {
    ports    = ["80"]
    protocol = "tcp"
  }
  direction     = "INGRESS"
  name          = "allow-lb-health-three-tier"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  priority      = 1000
  project       = "web-size-architecture"
  source_ranges = ["130.211.0.0/22", "209.85.152.0/22", "209.85.204.0/22", "35.191.0.0/16"]
  target_tags   = ["allow-healthcheck"]
}
# terraform import google_compute_firewall.allow_lb_health_three_tier projects/web-size-architecture/global/firewalls/allow-lb-health-three-tier
resource "google_compute_firewall" "allow_ssh_ingress_from_iap" {
  allow {
    ports    = ["22"]
    protocol = "tcp"
  }
  direction     = "INGRESS"
  name          = "allow-ssh-ingress-from-iap"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  priority      = 1000
  project       = "web-size-architecture"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["allow-ssh"]
}
# terraform import google_compute_firewall.allow_ssh_ingress_from_iap projects/web-size-architecture/global/firewalls/allow-ssh-ingress-from-iap
resource "google_compute_firewall" "default_allow_ssh" {
  allow {
    ports    = ["22"]
    protocol = "tcp"
  }
  description   = "Allow SSH from anywhere"
  direction     = "INGRESS"
  name          = "default-allow-ssh"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  priority      = 65534
  project       = "web-size-architecture"
  source_ranges = ["0.0.0.0/0"]
}
# terraform import google_compute_firewall.default_allow_ssh projects/web-size-architecture/global/firewalls/default-allow-ssh
resource "google_compute_firewall" "default_allow_icmp" {
  allow {
    protocol = "icmp"
  }
  description   = "Allow ICMP from anywhere"
  direction     = "INGRESS"
  name          = "default-allow-icmp"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  priority      = 65534
  project       = "web-size-architecture"
  source_ranges = ["0.0.0.0/0"]
}
# terraform import google_compute_firewall.default_allow_icmp projects/web-size-architecture/global/firewalls/default-allow-icmp
resource "google_compute_firewall" "default_allow_icmp_three_tier" {
  allow {
    protocol = "icmp"
  }
  direction     = "INGRESS"
  name          = "default-allow-icmp-three-tier"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  priority      = 65534
  project       = "web-size-architecture"
  source_ranges = ["0.0.0.0/0"]
}
# terraform import google_compute_firewall.default_allow_icmp_three_tier projects/web-size-architecture/global/firewalls/default-allow-icmp-three-tier
resource "google_compute_instance" "frontend_mig_4cqc" {
  boot_disk {
    auto_delete = true
    device_name = "persistent-disk-0"
    initialize_params {
      image = "https://www.googleapis.com/compute/beta/projects/centos-cloud/global/images/centos-7-v20211214"
      size  = 20
      type  = "pd-standard"
    }
    mode   = "READ_WRITE"
    source = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/zones/europe-west1-b/disks/frontend-mig-4cqc"
  }
  machine_type = "f1-micro"
  metadata = {
    created-by        = "projects/1016084318133/regions/europe-west1/instanceGroupManagers/frontend-mig"
    instance-template = "projects/1016084318133/global/instanceTemplates/frontend-template"
  }
  metadata_startup_script = "#! /bin/bash\n\n# Install NGINX\nsudo yum -y update; sudo yum clean all\nsudo yum -y install http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm; sudo yum -y makecache\nsudo yum -y install nginx-1.14.0\n\n# Remove default files we don't need\nsudo rm -f /etc/nginx/conf.d/default.conf\n\nsudo cat <<__EOF__>/etc/nginx/nginx.conf\npid /run/nginx.pid;\nworker_processes auto;\nworker_rlimit_nofile 1024;\n\nevents {\n        multi_accept on;\n        worker_connections 1024;\n}\n\nhttp {\n    upstream myapp {\n        server 10.0.2.4;\n    }\n\n    server {\n        listen 80 default_server;\n        server_name \"\";\n        location / {\n            proxy_pass http://myapp;\n            proxy_set_header Host \\$host;\n            proxy_http_version 1.1;\n            proxy_read_timeout 120s;\n        }\n    }\n}\n__EOF__\nsudo systemctl restart nginx"
  name                    = "frontend-mig-4cqc"
  network_interface {
    network            = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
    network_ip         = "10.0.1.3"
    stack_type         = "IPV4_ONLY"
    subnetwork         = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-1"
    subnetwork_project = "web-size-architecture"
  }
  project = "web-size-architecture"
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  service_account {
    email  = "1016084318133-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/pubsub", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_vtpm                 = true
  }
  tags = ["allow-healthcheck", "allow-http", "allow-ssh"]
  zone = "europe-west1-b"
}
# terraform import google_compute_instance.frontend_mig_4cqc projects/web-size-architecture/zones/europe-west1-b/instances/frontend-mig-4cqc
resource "google_compute_instance" "backend_mig_1b89" {
  boot_disk {
    auto_delete = true
    device_name = "persistent-disk-0"
    initialize_params {
      image = "https://www.googleapis.com/compute/beta/projects/debian-cloud/global/images/debian-10-buster-v20211209"
      size  = 10
      type  = "pd-standard"
    }
    mode   = "READ_WRITE"
    source = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/zones/europe-west1-b/disks/backend-mig-1b89"
  }
  machine_type = "f1-micro"
  metadata = {
    created-by        = "projects/1016084318133/regions/europe-west1/instanceGroupManagers/backend-mig"
    instance-template = "projects/1016084318133/global/instanceTemplates/backend-template"
  }
  metadata_startup_script = "#! /bin/bash\n  sudo apt-get update\n  sudo apt-get install -y git apache2\n  cd /var/www/html\n  sudo rm index.html -f\n  sudo git init\n  sudo git pull https://github.com/DmyMi/2048.git\n  ZONE=$(curl \"http://metadata.google.internal/computeMetadata/v1/instance/zone\" -H \"Metadata-Flavor: Google\")\n  sed -i \"s|zone-here|$ZONE|\" /var/www/html/index.html\n  sudo systemctl restart apache2"
  name                    = "backend-mig-1b89"
  network_interface {
    network            = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
    network_ip         = "10.0.2.2"
    stack_type         = "IPV4_ONLY"
    subnetwork         = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-2"
    subnetwork_project = "web-size-architecture"
  }
  project = "web-size-architecture"
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  service_account {
    email  = "1016084318133-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/pubsub", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_vtpm                 = true
  }
  tags = ["allow-healthcheck", "allow-ssh"]
  zone = "europe-west1-b"
}
# terraform import google_compute_instance.backend_mig_1b89 projects/web-size-architecture/zones/europe-west1-b/instances/backend-mig-1b89
resource "google_compute_firewall" "default_allow_internal" {
  allow {
    ports    = ["0-65535"]
    protocol = "tcp"
  }
  allow {
    ports    = ["0-65535"]
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }
  description   = "Allow internal traffic on the default network"
  direction     = "INGRESS"
  name          = "default-allow-internal"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  priority      = 65534
  project       = "web-size-architecture"
  source_ranges = ["10.128.0.0/9"]
}
# terraform import google_compute_firewall.default_allow_internal projects/web-size-architecture/global/firewalls/default-allow-internal
resource "google_compute_firewall" "default_allow_rdp" {
  allow {
    ports    = ["3389"]
    protocol = "tcp"
  }
  description   = "Allow RDP from anywhere"
  direction     = "INGRESS"
  name          = "default-allow-rdp"
  network       = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  priority      = 65534
  project       = "web-size-architecture"
  source_ranges = ["0.0.0.0/0"]
}
# terraform import google_compute_firewall.default_allow_rdp projects/web-size-architecture/global/firewalls/default-allow-rdp
resource "google_compute_health_check" "frontend_check" {
  check_interval_sec = 5
  healthy_threshold  = 2
  http_health_check {
    port               = 80
    port_specification = "USE_FIXED_PORT"
    proxy_header       = "NONE"
    request_path       = "/"
  }
  name                = "frontend-check"
  project             = "web-size-architecture"
  timeout_sec         = 5
  unhealthy_threshold = 2
}
# terraform import google_compute_health_check.frontend_check projects/web-size-architecture/global/healthChecks/frontend-check
resource "google_compute_instance" "backend_mig_vvpt" {
  boot_disk {
    auto_delete = true
    device_name = "persistent-disk-0"
    initialize_params {
      image = "https://www.googleapis.com/compute/beta/projects/debian-cloud/global/images/debian-10-buster-v20211209"
      size  = 10
      type  = "pd-standard"
    }
    mode   = "READ_WRITE"
    source = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/zones/europe-west1-c/disks/backend-mig-vvpt"
  }
  machine_type = "f1-micro"
  metadata = {
    instance-template = "projects/1016084318133/global/instanceTemplates/backend-template"
    created-by        = "projects/1016084318133/regions/europe-west1/instanceGroupManagers/backend-mig"
  }
  metadata_startup_script = "#! /bin/bash\n  sudo apt-get update\n  sudo apt-get install -y git apache2\n  cd /var/www/html\n  sudo rm index.html -f\n  sudo git init\n  sudo git pull https://github.com/DmyMi/2048.git\n  ZONE=$(curl \"http://metadata.google.internal/computeMetadata/v1/instance/zone\" -H \"Metadata-Flavor: Google\")\n  sed -i \"s|zone-here|$ZONE|\" /var/www/html/index.html\n  sudo systemctl restart apache2"
  name                    = "backend-mig-vvpt"
  network_interface {
    network            = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
    network_ip         = "10.0.2.3"
    stack_type         = "IPV4_ONLY"
    subnetwork         = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-2"
    subnetwork_project = "web-size-architecture"
  }
  project = "web-size-architecture"
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  service_account {
    email  = "1016084318133-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/pubsub", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_vtpm                 = true
  }
  tags = ["allow-healthcheck", "allow-ssh"]
  zone = "europe-west1-c"
}
# terraform import google_compute_instance.backend_mig_vvpt projects/web-size-architecture/zones/europe-west1-c/instances/backend-mig-vvpt
resource "google_compute_health_check" "backend_check" {
  check_interval_sec = 5
  healthy_threshold  = 2
  name               = "backend-check"
  project            = "web-size-architecture"
  tcp_health_check {
    port               = 80
    port_specification = "USE_FIXED_PORT"
    proxy_header       = "NONE"
  }
  timeout_sec         = 5
  unhealthy_threshold = 2
}
# terraform import google_compute_health_check.backend_check projects/web-size-architecture/global/healthChecks/backend-check
resource "google_compute_global_forwarding_rule" "frontend_lb" {
  ip_address            = "34.102.178.165"
  ip_protocol           = "TCP"
  ip_version            = "IPV4"
  load_balancing_scheme = "EXTERNAL"
  name                  = "frontend-lb"
  port_range            = "80-80"
  project               = "web-size-architecture"
  target                = "https://www.googleapis.com/compute/beta/projects/web-size-architecture/global/targetHttpProxies/frontend-proxy"
}
# terraform import google_compute_global_forwarding_rule.frontend_lb projects/web-size-architecture/global/forwardingRules/frontend-lb
resource "google_compute_instance_template" "frontend_template" {
  disk {
    auto_delete  = true
    boot         = true
    device_name  = "persistent-disk-0"
    disk_size_gb = 20
    mode         = "READ_WRITE"
    source_image = "projects/centos-cloud/global/images/family/centos-7"
    type         = "PERSISTENT"
  }
  labels = {
    managed-by-cnrm = "true"
  }
  machine_type = "f1-micro"
  metadata = {
    startup-script = "#! /bin/bash\n\n# Install NGINX\nsudo yum -y update; sudo yum clean all\nsudo yum -y install http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm; sudo yum -y makecache\nsudo yum -y install nginx-1.14.0\n\n# Remove default files we don't need\nsudo rm -f /etc/nginx/conf.d/default.conf\n\nsudo cat <<__EOF__>/etc/nginx/nginx.conf\npid /run/nginx.pid;\nworker_processes auto;\nworker_rlimit_nofile 1024;\n\nevents {\n        multi_accept on;\n        worker_connections 1024;\n}\n\nhttp {\n    upstream myapp {\n        server 10.0.2.4;\n    }\n\n    server {\n        listen 80 default_server;\n        server_name \"\";\n        location / {\n            proxy_pass http://myapp;\n            proxy_set_header Host \\$host;\n            proxy_http_version 1.1;\n            proxy_read_timeout 120s;\n        }\n    }\n}\n__EOF__\nsudo systemctl restart nginx"
  }
  name = "frontend-template"
  network_interface {
    network            = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
    subnetwork         = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-1"
    subnetwork_project = "web-size-architecture"
  }
  project = "web-size-architecture"
  region  = "europe-west1"
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  service_account {
    email  = "default"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/pubsub", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
  tags = ["allow-healthcheck", "allow-http", "allow-ssh"]
}
# terraform import google_compute_instance_template.frontend_template projects/web-size-architecture/global/instanceTemplates/frontend-template
resource "google_compute_instance" "frontend_mig_gmdc" {
  boot_disk {
    auto_delete = true
    device_name = "persistent-disk-0"
    initialize_params {
      image = "https://www.googleapis.com/compute/beta/projects/centos-cloud/global/images/centos-7-v20211214"
      size  = 20
      type  = "pd-standard"
    }
    mode   = "READ_WRITE"
    source = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/zones/europe-west1-c/disks/frontend-mig-gmdc"
  }
  machine_type = "f1-micro"
  metadata = {
    instance-template = "projects/1016084318133/global/instanceTemplates/frontend-template"
    created-by        = "projects/1016084318133/regions/europe-west1/instanceGroupManagers/frontend-mig"
  }
  metadata_startup_script = "#! /bin/bash\n\n# Install NGINX\nsudo yum -y update; sudo yum clean all\nsudo yum -y install http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm; sudo yum -y makecache\nsudo yum -y install nginx-1.14.0\n\n# Remove default files we don't need\nsudo rm -f /etc/nginx/conf.d/default.conf\n\nsudo cat <<__EOF__>/etc/nginx/nginx.conf\npid /run/nginx.pid;\nworker_processes auto;\nworker_rlimit_nofile 1024;\n\nevents {\n        multi_accept on;\n        worker_connections 1024;\n}\n\nhttp {\n    upstream myapp {\n        server 10.0.2.4;\n    }\n\n    server {\n        listen 80 default_server;\n        server_name \"\";\n        location / {\n            proxy_pass http://myapp;\n            proxy_set_header Host \\$host;\n            proxy_http_version 1.1;\n            proxy_read_timeout 120s;\n        }\n    }\n}\n__EOF__\nsudo systemctl restart nginx"
  name                    = "frontend-mig-gmdc"
  network_interface {
    network            = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
    network_ip         = "10.0.1.2"
    stack_type         = "IPV4_ONLY"
    subnetwork         = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-1"
    subnetwork_project = "web-size-architecture"
  }
  project = "web-size-architecture"
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  service_account {
    email  = "1016084318133-compute@developer.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/pubsub", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_vtpm                 = true
  }
  tags = ["allow-healthcheck", "allow-http", "allow-ssh"]
  zone = "europe-west1-c"
}
# terraform import google_compute_instance.frontend_mig_gmdc projects/web-size-architecture/zones/europe-west1-c/instances/frontend-mig-gmdc
resource "google_compute_route" "default_route_2a496f9e184165f1" {
  description = "Default local route to the subnetwork 10.162.0.0/20."
  dest_range  = "10.162.0.0/20"
  name        = "default-route-2a496f9e184165f1"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_2a496f9e184165f1 projects/web-size-architecture/global/routes/default-route-2a496f9e184165f1
resource "google_compute_route" "default_route_2725f7c8d8bcd315" {
  description = "Default local route to the subnetwork 10.132.0.0/20."
  dest_range  = "10.132.0.0/20"
  name        = "default-route-2725f7c8d8bcd315"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_2725f7c8d8bcd315 projects/web-size-architecture/global/routes/default-route-2725f7c8d8bcd315
resource "google_compute_route" "default_route_1fbd304d9a8761ea" {
  description = "Default local route to the subnetwork 10.0.2.0/24."
  dest_range  = "10.0.2.0/24"
  name        = "default-route-1fbd304d9a8761ea"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_1fbd304d9a8761ea projects/web-size-architecture/global/routes/default-route-1fbd304d9a8761ea
resource "google_compute_route" "default_route_207baa94df031550" {
  description = "Default local route to the subnetwork 10.150.0.0/20."
  dest_range  = "10.150.0.0/20"
  name        = "default-route-207baa94df031550"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_207baa94df031550 projects/web-size-architecture/global/routes/default-route-207baa94df031550
resource "google_compute_route" "default_route_4ef78328c97a62f0" {
  description = "Default local route to the subnetwork 10.148.0.0/20."
  dest_range  = "10.148.0.0/20"
  name        = "default-route-4ef78328c97a62f0"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_4ef78328c97a62f0 projects/web-size-architecture/global/routes/default-route-4ef78328c97a62f0
resource "google_compute_network" "default" {
  auto_create_subnetworks = true
  description             = "Default network for the project"
  name                    = "default"
  project                 = "web-size-architecture"
  routing_mode            = "REGIONAL"
}
# terraform import google_compute_network.default projects/web-size-architecture/global/networks/default
resource "google_compute_instance_template" "backend_template" {
  disk {
    auto_delete  = true
    boot         = true
    device_name  = "persistent-disk-0"
    disk_size_gb = 10
    mode         = "READ_WRITE"
    source_image = "projects/debian-cloud/global/images/family/debian-10"
    type         = "PERSISTENT"
  }
  labels = {
    managed-by-cnrm = "true"
  }
  machine_type = "f1-micro"
  metadata = {
    startup-script = "#! /bin/bash\n  sudo apt-get update\n  sudo apt-get install -y git apache2\n  cd /var/www/html\n  sudo rm index.html -f\n  sudo git init\n  sudo git pull https://github.com/DmyMi/2048.git\n  ZONE=$(curl \"http://metadata.google.internal/computeMetadata/v1/instance/zone\" -H \"Metadata-Flavor: Google\")\n  sed -i \"s|zone-here|$ZONE|\" /var/www/html/index.html\n  sudo systemctl restart apache2"
  }
  name = "backend-template"
  network_interface {
    network            = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
    subnetwork         = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-2"
    subnetwork_project = "web-size-architecture"
  }
  project = "web-size-architecture"
  region  = "europe-west1"
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  service_account {
    email  = "default"
    scopes = ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/pubsub", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/trace.append"]
  }
  tags = ["allow-healthcheck", "allow-ssh"]
}
# terraform import google_compute_instance_template.backend_template projects/web-size-architecture/global/instanceTemplates/backend-template
resource "google_compute_route" "default_route_3fb23eb91c551322" {
  description = "Default local route to the subnetwork 10.152.0.0/20."
  dest_range  = "10.152.0.0/20"
  name        = "default-route-3fb23eb91c551322"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_3fb23eb91c551322 projects/web-size-architecture/global/routes/default-route-3fb23eb91c551322
resource "google_compute_route" "default_route_5a4203c1607b9ea2" {
  description = "Default local route to the subnetwork 10.158.0.0/20."
  dest_range  = "10.158.0.0/20"
  name        = "default-route-5a4203c1607b9ea2"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_5a4203c1607b9ea2 projects/web-size-architecture/global/routes/default-route-5a4203c1607b9ea2
resource "google_compute_route" "default_route_1c80e815e7545c95" {
  description = "Default local route to the subnetwork 10.192.0.0/20."
  dest_range  = "10.192.0.0/20"
  name        = "default-route-1c80e815e7545c95"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_1c80e815e7545c95 projects/web-size-architecture/global/routes/default-route-1c80e815e7545c95
resource "google_compute_route" "default_route_4cd0529020c7d17d" {
  description = "Default local route to the subnetwork 10.194.0.0/20."
  dest_range  = "10.194.0.0/20"
  name        = "default-route-4cd0529020c7d17d"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_4cd0529020c7d17d projects/web-size-architecture/global/routes/default-route-4cd0529020c7d17d
resource "google_compute_route" "default_route_324d6e582b4c8f9e" {
  description = "Default local route to the subnetwork 10.178.0.0/20."
  dest_range  = "10.178.0.0/20"
  name        = "default-route-324d6e582b4c8f9e"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_324d6e582b4c8f9e projects/web-size-architecture/global/routes/default-route-324d6e582b4c8f9e
resource "google_compute_route" "default_route_4e05c3362ad1f3ab" {
  description = "Default local route to the subnetwork 10.0.1.0/24."
  dest_range  = "10.0.1.0/24"
  name        = "default-route-4e05c3362ad1f3ab"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_4e05c3362ad1f3ab projects/web-size-architecture/global/routes/default-route-4e05c3362ad1f3ab
resource "google_compute_network" "three_tier" {
  mtu          = 1460
  name         = "three-tier"
  project      = "web-size-architecture"
  routing_mode = "REGIONAL"
}
# terraform import google_compute_network.three_tier projects/web-size-architecture/global/networks/three-tier
resource "google_compute_route" "default_route_3f278870e0f644ac" {
  description = "Default local route to the subnetwork 10.172.0.0/20."
  dest_range  = "10.172.0.0/20"
  name        = "default-route-3f278870e0f644ac"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_3f278870e0f644ac projects/web-size-architecture/global/routes/default-route-3f278870e0f644ac
resource "google_compute_route" "default_route_7cdc5f71cb993c03" {
  description = "Default local route to the subnetwork 10.186.0.0/20."
  dest_range  = "10.186.0.0/20"
  name        = "default-route-7cdc5f71cb993c03"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_7cdc5f71cb993c03 projects/web-size-architecture/global/routes/default-route-7cdc5f71cb993c03
resource "google_compute_route" "default_route_ce73650ca4e1025f" {
  description = "Default local route to the subnetwork 10.164.0.0/20."
  dest_range  = "10.164.0.0/20"
  name        = "default-route-ce73650ca4e1025f"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_ce73650ca4e1025f projects/web-size-architecture/global/routes/default-route-ce73650ca4e1025f
resource "google_compute_route" "default_route_9a7f3e153c246154" {
  description = "Default local route to the subnetwork 10.146.0.0/20."
  dest_range  = "10.146.0.0/20"
  name        = "default-route-9a7f3e153c246154"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_9a7f3e153c246154 projects/web-size-architecture/global/routes/default-route-9a7f3e153c246154
resource "google_compute_route" "default_route_918e3fc5517980b0" {
  description = "Default local route to the subnetwork 10.170.0.0/20."
  dest_range  = "10.170.0.0/20"
  name        = "default-route-918e3fc5517980b0"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_918e3fc5517980b0 projects/web-size-architecture/global/routes/default-route-918e3fc5517980b0
resource "google_compute_route" "default_route_adf67d3c4a7ffbe4" {
  description = "Default local route to the subnetwork 10.138.0.0/20."
  dest_range  = "10.138.0.0/20"
  name        = "default-route-adf67d3c4a7ffbe4"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_adf67d3c4a7ffbe4 projects/web-size-architecture/global/routes/default-route-adf67d3c4a7ffbe4
resource "google_compute_route" "default_route_e8a94bba8932ac04" {
  description = "Default local route to the subnetwork 10.128.0.0/20."
  dest_range  = "10.128.0.0/20"
  name        = "default-route-e8a94bba8932ac04"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_e8a94bba8932ac04 projects/web-size-architecture/global/routes/default-route-e8a94bba8932ac04
resource "google_compute_route" "default_route_e761fefa1033f5b6" {
  description      = "Default route to the Internet."
  dest_range       = "0.0.0.0/0"
  name             = "default-route-e761fefa1033f5b6"
  network          = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  next_hop_gateway = "https://www.googleapis.com/compute/beta/projects/web-size-architecture/global/gateways/default-internet-gateway"
  priority         = 1000
  project          = "web-size-architecture"
}
# terraform import google_compute_route.default_route_e761fefa1033f5b6 projects/web-size-architecture/global/routes/default-route-e761fefa1033f5b6
resource "google_compute_route" "default_route_ef82ccc41c3c734b" {
  description = "Default local route to the subnetwork 10.154.0.0/20."
  dest_range  = "10.154.0.0/20"
  name        = "default-route-ef82ccc41c3c734b"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_ef82ccc41c3c734b projects/web-size-architecture/global/routes/default-route-ef82ccc41c3c734b
resource "google_compute_route" "default_route_e04e01c9ed7a0409" {
  description = "Default local route to the subnetwork 10.160.0.0/20."
  dest_range  = "10.160.0.0/20"
  name        = "default-route-e04e01c9ed7a0409"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_e04e01c9ed7a0409 projects/web-size-architecture/global/routes/default-route-e04e01c9ed7a0409
resource "google_compute_forwarding_rule" "backend_lb" {
  backend_service       = "https://www.googleapis.com/compute/beta/projects/web-size-architecture/regions/europe-west1/backendServices/backend-bs"
  ip_address            = "10.0.2.4"
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL"
  name                  = "backend-lb"
  network               = "https://www.googleapis.com/compute/beta/projects/web-size-architecture/global/networks/three-tier"
  network_tier          = "PREMIUM"
  ports                 = ["80"]
  project               = "web-size-architecture"
  region                = "europe-west1"
  subnetwork            = "https://www.googleapis.com/compute/beta/projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-2"
}
# terraform import google_compute_forwarding_rule.backend_lb projects/web-size-architecture/regions/europe-west1/forwardingRules/backend-lb
resource "google_compute_route" "default_route_cfe57c491407a6ac" {
  description = "Default local route to the subnetwork 10.182.0.0/20."
  dest_range  = "10.182.0.0/20"
  name        = "default-route-cfe57c491407a6ac"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_cfe57c491407a6ac projects/web-size-architecture/global/routes/default-route-cfe57c491407a6ac
resource "google_compute_route" "default_route_fa17724f9c1129d4" {
  description = "Default local route to the subnetwork 10.188.0.0/20."
  dest_range  = "10.188.0.0/20"
  name        = "default-route-fa17724f9c1129d4"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_fa17724f9c1129d4 projects/web-size-architecture/global/routes/default-route-fa17724f9c1129d4
resource "google_compute_route" "default_route_1df85156120b6c99" {
  description = "Default local route to the subnetwork 10.168.0.0/20."
  dest_range  = "10.168.0.0/20"
  name        = "default-route-1df85156120b6c99"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_1df85156120b6c99 projects/web-size-architecture/global/routes/default-route-1df85156120b6c99
resource "google_compute_route" "default_route_725720733e6c83be" {
  description = "Default local route to the subnetwork 10.166.0.0/20."
  dest_range  = "10.166.0.0/20"
  name        = "default-route-725720733e6c83be"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_725720733e6c83be projects/web-size-architecture/global/routes/default-route-725720733e6c83be
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.140.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-east1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-east1/subnetworks/default
resource "google_compute_route" "default_route_ad583b1607e910c3" {
  description = "Default local route to the subnetwork 10.184.0.0/20."
  dest_range  = "10.184.0.0/20"
  name        = "default-route-ad583b1607e910c3"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_ad583b1607e910c3 projects/web-size-architecture/global/routes/default-route-ad583b1607e910c3
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.160.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-south1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-south1/subnetworks/default
resource "google_compute_route" "default_route_edfebcb0b885743a" {
  description = "Default local route to the subnetwork 10.174.0.0/20."
  dest_range  = "10.174.0.0/20"
  name        = "default-route-edfebcb0b885743a"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_edfebcb0b885743a projects/web-size-architecture/global/routes/default-route-edfebcb0b885743a
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.184.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-southeast2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-southeast2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.152.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "australia-southeast1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/australia-southeast1/subnetworks/default
resource "google_compute_route" "default_route_d11da316adf1cef2" {
  description = "Default local route to the subnetwork 10.156.0.0/20."
  dest_range  = "10.156.0.0/20"
  name        = "default-route-d11da316adf1cef2"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_d11da316adf1cef2 projects/web-size-architecture/global/routes/default-route-d11da316adf1cef2
resource "google_compute_route" "default_route_671729ce9c618a74" {
  description = "Default local route to the subnetwork 10.142.0.0/20."
  dest_range  = "10.142.0.0/20"
  name        = "default-route-671729ce9c618a74"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_671729ce9c618a74 projects/web-size-architecture/global/routes/default-route-671729ce9c618a74
resource "google_compute_route" "default_route_5d77f74752226eb1" {
  description = "Default local route to the subnetwork 10.180.0.0/20."
  dest_range  = "10.180.0.0/20"
  name        = "default-route-5d77f74752226eb1"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_5d77f74752226eb1 projects/web-size-architecture/global/routes/default-route-5d77f74752226eb1
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.190.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-south2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-south2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.192.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "australia-southeast2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/australia-southeast2/subnetworks/default
resource "google_compute_subnetwork" "private_subnet_1" {
  ip_cidr_range              = "10.0.1.0/24"
  name                       = "private-subnet-1"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-west1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.private_subnet_1 projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-1
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.178.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-northeast3"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-northeast3/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.186.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-central2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/europe-central2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.170.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-east2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-east2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.154.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-west2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/europe-west2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.148.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-southeast1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-southeast1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.150.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "us-east4"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/us-east4/subnetworks/default
resource "google_compute_route" "default_route_85e16f34cff4f9fe" {
  description = "Default local route to the subnetwork 10.140.0.0/20."
  dest_range  = "10.140.0.0/20"
  name        = "default-route-85e16f34cff4f9fe"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_85e16f34cff4f9fe projects/web-size-architecture/global/routes/default-route-85e16f34cff4f9fe
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.128.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "us-central1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/us-central1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.156.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-west3"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/europe-west3/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.132.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-west1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/europe-west1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.166.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-north1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/europe-north1/subnetworks/default
resource "google_compute_region_backend_service" "backend_bs" {
  health_checks         = ["https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/healthChecks/backend-check"]
  load_balancing_scheme = "INTERNAL"
  name                  = "backend-bs"
  network               = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  project               = "web-size-architecture"
  protocol              = "TCP"
  region                = "europe-west1"
  session_affinity      = "NONE"
  timeout_sec           = 30
}
# terraform import google_compute_region_backend_service.backend_bs projects/web-size-architecture/regions/europe-west1/backendServices/backend-bs
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.158.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "southamerica-east1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/southamerica-east1/subnetworks/default
resource "google_project_service" "bigquery_googleapis_com" {
  project = "1016084318133"
  service = "bigquery.googleapis.com"
}
# terraform import google_project_service.bigquery_googleapis_com 1016084318133/bigquery.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.180.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "us-west3"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/us-west3/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.174.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-northeast2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-northeast2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.188.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "northamerica-northeast2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/northamerica-northeast2/subnetworks/default
resource "google_project_service" "cloudapis_googleapis_com" {
  project = "1016084318133"
  service = "cloudapis.googleapis.com"
}
# terraform import google_project_service.cloudapis_googleapis_com 1016084318133/cloudapis.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.168.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "us-west2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/us-west2/subnetworks/default
resource "google_compute_route" "default_route_92d44aa64dded818" {
  description      = "Default route to the Internet."
  dest_range       = "0.0.0.0/0"
  name             = "default-route-92d44aa64dded818"
  network          = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  next_hop_gateway = "https://www.googleapis.com/compute/beta/projects/web-size-architecture/global/gateways/default-internet-gateway"
  priority         = 1000
  project          = "web-size-architecture"
}
# terraform import google_compute_route.default_route_92d44aa64dded818 projects/web-size-architecture/global/routes/default-route-92d44aa64dded818
resource "google_compute_url_map" "frontend_map" {
  default_service = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/backendServices/frontend-bs"
  host_rule {
    hosts        = ["*"]
    path_matcher = "pathmap"
  }
  name = "frontend-map"
  path_matcher {
    default_service = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/backendServices/frontend-bs"
    name            = "pathmap"
    path_rule {
      paths   = ["/*"]
      service = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/backendServices/frontend-bs"
    }
  }
  project = "web-size-architecture"
}
# terraform import google_compute_url_map.frontend_map projects/web-size-architecture/global/urlMaps/frontend-map
resource "google_project_service" "datastore_googleapis_com" {
  project = "1016084318133"
  service = "datastore.googleapis.com"
}
# terraform import google_project_service.datastore_googleapis_com 1016084318133/datastore.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.146.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "asia-northeast1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/asia-northeast1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.162.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "northamerica-northeast1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/northamerica-northeast1/subnetworks/default
resource "google_project_service" "cloudasset_googleapis_com" {
  project = "1016084318133"
  service = "cloudasset.googleapis.com"
}
# terraform import google_project_service.cloudasset_googleapis_com 1016084318133/cloudasset.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.164.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-west4"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/europe-west4/subnetworks/default
resource "google_compute_target_http_proxy" "frontend_proxy" {
  name    = "frontend-proxy"
  project = "web-size-architecture"
  url_map = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/urlMaps/frontend-map"
}
# terraform import google_compute_target_http_proxy.frontend_proxy projects/web-size-architecture/global/targetHttpProxies/frontend-proxy
resource "google_project_service" "logging_googleapis_com" {
  project = "1016084318133"
  service = "logging.googleapis.com"
}
# terraform import google_project_service.logging_googleapis_com 1016084318133/logging.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.172.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-west6"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/europe-west6/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.194.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "southamerica-west1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/southamerica-west1/subnetworks/default
resource "google_compute_subnetwork" "private_subnet_2" {
  ip_cidr_range              = "10.0.2.0/24"
  name                       = "private-subnet-2"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/three-tier"
  private_ip_google_access   = true
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "europe-west1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.private_subnet_2 projects/web-size-architecture/regions/europe-west1/subnetworks/private-subnet-2
resource "google_project_service" "clouddebugger_googleapis_com" {
  project = "1016084318133"
  service = "clouddebugger.googleapis.com"
}
# terraform import google_project_service.clouddebugger_googleapis_com 1016084318133/clouddebugger.googleapis.com
resource "google_project_service" "compute_googleapis_com" {
  project = "1016084318133"
  service = "compute.googleapis.com"
}
# terraform import google_project_service.compute_googleapis_com 1016084318133/compute.googleapis.com
resource "google_service_account" "1016084318133_compute" {
  account_id   = "1016084318133-compute"
  display_name = "Compute Engine default service account"
  project      = "web-size-architecture"
}
# terraform import google_service_account.1016084318133_compute projects/web-size-architecture/serviceAccounts/1016084318133-compute@web-size-architecture.iam.gserviceaccount.com
resource "google_project_service" "sql_component_googleapis_com" {
  project = "1016084318133"
  service = "sql-component.googleapis.com"
}
# terraform import google_project_service.sql_component_googleapis_com 1016084318133/sql-component.googleapis.com
resource "google_project_service" "oslogin_googleapis_com" {
  project = "1016084318133"
  service = "oslogin.googleapis.com"
}
# terraform import google_project_service.oslogin_googleapis_com 1016084318133/oslogin.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.142.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "us-east1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/us-east1/subnetworks/default
resource "google_compute_route" "default_route_d82be8e66a77e07e" {
  description = "Default local route to the subnetwork 10.190.0.0/20."
  dest_range  = "10.190.0.0/20"
  name        = "default-route-d82be8e66a77e07e"
  network     = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  project     = "web-size-architecture"
}
# terraform import google_compute_route.default_route_d82be8e66a77e07e projects/web-size-architecture/global/routes/default-route-d82be8e66a77e07e
resource "google_project_service" "bigquerystorage_googleapis_com" {
  project = "1016084318133"
  service = "bigquerystorage.googleapis.com"
}
# terraform import google_project_service.bigquerystorage_googleapis_com 1016084318133/bigquerystorage.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.138.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "us-west1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/us-west1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.182.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/web-size-architecture/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "web-size-architecture"
  purpose                    = "PRIVATE"
  region                     = "us-west4"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/web-size-architecture/regions/us-west4/subnetworks/default
resource "google_project_service" "storage_api_googleapis_com" {
  project = "1016084318133"
  service = "storage-api.googleapis.com"
}
# terraform import google_project_service.storage_api_googleapis_com 1016084318133/storage-api.googleapis.com
resource "google_project_service" "storage_googleapis_com" {
  project = "1016084318133"
  service = "storage.googleapis.com"
}
# terraform import google_project_service.storage_googleapis_com 1016084318133/storage.googleapis.com
resource "google_project_service" "storage_component_googleapis_com" {
  project = "1016084318133"
  service = "storage-component.googleapis.com"
}
# terraform import google_project_service.storage_component_googleapis_com 1016084318133/storage-component.googleapis.com
resource "google_project_service" "cloudtrace_googleapis_com" {
  project = "1016084318133"
  service = "cloudtrace.googleapis.com"
}
# terraform import google_project_service.cloudtrace_googleapis_com 1016084318133/cloudtrace.googleapis.com
resource "google_project_service" "monitoring_googleapis_com" {
  project = "1016084318133"
  service = "monitoring.googleapis.com"
}
# terraform import google_project_service.monitoring_googleapis_com 1016084318133/monitoring.googleapis.com
resource "google_project_service" "servicemanagement_googleapis_com" {
  project = "1016084318133"
  service = "servicemanagement.googleapis.com"
}
# terraform import google_project_service.servicemanagement_googleapis_com 1016084318133/servicemanagement.googleapis.com
resource "google_project_service" "serviceusage_googleapis_com" {
  project = "1016084318133"
  service = "serviceusage.googleapis.com"
}
# terraform import google_project_service.serviceusage_googleapis_com 1016084318133/serviceusage.googleapis.com
