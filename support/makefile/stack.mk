<---stack-------->: ## -----------------------------------------------------------------------
start: ## Start the MariaDB test database and wait until healthy
	@echo "Starting MariaDB..."
	@$(DOCKER_COMPOSE) up -d --wait mariadb
	@echo "MariaDB is healthy."
.PHONY: start

stop: ## Stop and remove all containers
	@echo "Stopping and removing all containers..."
	@$(DOCKER_COMPOSE) down --remove-orphans
	@echo "All containers stopped and removed."
.PHONY: stop

restart: stop start ## Restart all containers
.PHONY: restart

status: ## Show status of all containers
	@$(DOCKER_COMPOSE) ps -a
.PHONY: status

logs: ## Show logs from all containers
	$(DOCKER_COMPOSE) logs -f
.PHONY: logs
