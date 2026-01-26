//! Bitcoin Deposits Service Coordinator

use std::ops::Deref;
use std::sync::Arc;
use lightning::util::logger::Logger as LdkLogger;

use crate::handler::DepositsHandler;
use super::{
    LightningEventService, PaymentOrchestrationService,
    ReservesManagementService, ServiceError, DepositsServiceConfig
};

/// Main Bitcoin Deposits service coordinator
/// This orchestrates all the individual services
pub struct DepositsService<L: Deref + Clone + Send + Sync>
where
    L::Target: LdkLogger,
{
    /// Core Bitcoin Deposits protocol handler
    handler: Arc<DepositsHandler<L>>,
    
    /// Lightning event handling service
    lightning_events: Arc<LightningEventService<L>>,

    // NWC server service removed - use real NWCService from src/nwc_service.rs

    /// Payment orchestration service
    payment_orchestrator: Arc<PaymentOrchestrationService<L>>,
    
    /// Reserves management service
    reserves_manager: Arc<ReservesManagementService<L>>,
    
    /// Service configuration
    config: DepositsServiceConfig,
    
    /// Logger
    logger: L,
}

impl<L: Deref + Clone + Send + Sync> DepositsService<L>
where
    L::Target: LdkLogger,
{
    /// Create new Bitcoin Deposits service coordinator
    pub fn new(
        handler: Arc<DepositsHandler<L>>,
        config: DepositsServiceConfig,
        logger: L,
    ) -> Result<Self, ServiceError> {
        // Create Lightning event service
        let mut lightning_events = LightningEventService::new(
            Arc::clone(&handler),
            logger.clone(),
        );
        
        // Create reserves management service
        let reserves_manager = Arc::new(ReservesManagementService::new(
            Arc::clone(&handler),
            std::time::Duration::from_secs(config.reserves_monitoring_interval_secs),
            config.excess_reserves_threshold_msat,
            logger.clone(),
        ));
        
        // Wire up the lightning events service to use the reserves manager
        lightning_events.set_reserves_manager(Arc::clone(&reserves_manager));
        let lightning_events = Arc::new(lightning_events);
        
        // Create other services
        let payment_orchestrator = Arc::new(PaymentOrchestrationService::new(logger.clone()));

        Ok(Self {
            handler,
            lightning_events,
            payment_orchestrator,
            reserves_manager,
            config,
            logger,
        })
    }
    
    /// Create new Bitcoin Deposits service coordinator from a handler reference
    /// This method works with the Node API that returns handler references
    /*
    pub fn new_from_handler_ref(
        handler_ref: &DepositsHandler<L>,
        config: DepositsServiceConfig,
        logger: L,
    ) -> Result<Self, ServiceError> 
    where 
        L: 'static
    {
        // TODO: Fix this after implementing proper service constructors
        panic!("Service coordinator constructor not yet implemented");
        // Create reserves management service that works with references
        let reserves_manager = Arc::new(ReservesManagementService::new_from_ref(
            handler_ref,
            std::time::Duration::from_secs(config.reserves_monitoring_interval_secs),
            config.excess_reserves_threshold_msat,
            logger.clone(),
        ));
        
        // Wire up the lightning events service to use the reserves manager
        lightning_events.set_reserves_manager(Arc::clone(&reserves_manager));
        let lightning_events = Arc::new(lightning_events);
        
        // Create other services
        let nwc_server = Arc::new(NostrWalletConnectService::new(logger.clone()));
        let payment_orchestrator = Arc::new(PaymentOrchestrationService::new(logger.clone()));
        
        // We need to create a dummy Arc for the struct, but the services will use their own handler references
        // This is a transitional approach until we can modify the Node API to provide Arc directly
        // TODO: Fix after implementing new_for_testing
        panic!("Placeholder service coordinator not yet implemented")
    }
    */
    
    /// Get the core Bitcoin Deposits handler
    pub fn handler(&self) -> &Arc<DepositsHandler<L>> {
        &self.handler
    }
    
    /// Get the Lightning event service
    pub fn lightning_events(&self) -> &Arc<LightningEventService<L>> {
        &self.lightning_events
    }
    
    /// Get the reserves management service
    pub fn reserves_manager(&self) -> &Arc<ReservesManagementService<L>> {
        &self.reserves_manager
    }
    
    /// Get the payment orchestration service
    pub fn payment_orchestrator(&self) -> &Arc<PaymentOrchestrationService<L>> {
        &self.payment_orchestrator
    }

    // NWC server removed - use real NWCService from src/nwc_service.rs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use lightning::util::test_utils::TestLogger;
    use crate::handler::DepositsHandler;

    fn create_test_handler() -> Arc<DepositsHandler<Arc<TestLogger>>> {
        let logger = Arc::new(TestLogger::new());
        Arc::new(DepositsHandler::new_for_testing(logger))
    }

    fn create_test_config() -> DepositsServiceConfig {
        DepositsServiceConfig {
            enable_nwc_server: false,
            nwc_relay_urls: vec![],
            reserves_monitoring_interval_secs: 60,
            excess_reserves_threshold_msat: 10_000,
        }
    }

    #[test]
    fn test_service_creation() {
        let handler = create_test_handler();
        let config = create_test_config();
        let logger = Arc::new(TestLogger::new());

        let result = DepositsService::new(handler, config, logger);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handler_accessor() {
        let handler = create_test_handler();
        let config = create_test_config();
        let logger = Arc::new(TestLogger::new());

        let service = DepositsService::new(handler.clone(), config, logger).unwrap();

        // Should return the same handler
        let returned_handler = service.handler();
        assert!(Arc::ptr_eq(&handler, returned_handler));
    }

    #[test]
    fn test_lightning_events_accessor() {
        let handler = create_test_handler();
        let config = create_test_config();
        let logger = Arc::new(TestLogger::new());

        let service = DepositsService::new(handler, config, logger).unwrap();

        // Should return a lightning events service
        let _lightning_events = service.lightning_events();
    }

    #[test]
    fn test_reserves_manager_accessor() {
        let handler = create_test_handler();
        let config = create_test_config();
        let logger = Arc::new(TestLogger::new());

        let service = DepositsService::new(handler, config, logger).unwrap();

        // Should return a reserves manager
        let _reserves_manager = service.reserves_manager();
    }

    #[test]
    fn test_payment_orchestrator_accessor() {
        let handler = create_test_handler();
        let config = create_test_config();
        let logger = Arc::new(TestLogger::new());

        let service = DepositsService::new(handler, config, logger).unwrap();

        // Should return a payment orchestrator
        let _payment_orchestrator = service.payment_orchestrator();
    }

    #[test]
    fn test_service_with_custom_config() {
        let handler = create_test_handler();
        let config = DepositsServiceConfig {
            enable_nwc_server: true,
            nwc_relay_urls: vec!["wss://relay.example.com".to_string()],
            reserves_monitoring_interval_secs: 120,  // 2 minutes
            excess_reserves_threshold_msat: 50_000,  // 50k msat
        };
        let logger = Arc::new(TestLogger::new());

        let result = DepositsService::new(handler, config, logger);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deposits_service_config_fields() {
        let config = DepositsServiceConfig {
            enable_nwc_server: false,
            nwc_relay_urls: vec![],
            reserves_monitoring_interval_secs: 30,
            excess_reserves_threshold_msat: 100_000,
        };

        assert_eq!(config.enable_nwc_server, false);
        assert!(config.nwc_relay_urls.is_empty());
        assert_eq!(config.reserves_monitoring_interval_secs, 30);
        assert_eq!(config.excess_reserves_threshold_msat, 100_000);
    }
}