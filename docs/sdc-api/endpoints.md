# SDC endpoint inventory

Generated from the vendored OpenAPI export — see [`README.md`](README.md)
for provenance. Do not hand-edit; regenerate with `scripts/gen-endpoint-inventory.py`.

`Security Director Cloud APIs` v1.0.0 · 234 paths · 377 operations · 63 groups

Base URL: `https://api.sdcloud.juniperclouds.net/`

## Groups

| Group | Ops |
|---|---:|
| [IAM](#iam) | 10 |
| [Site Management](#site-management) | 20 |
| [Service Location Management](#service-location-management) | 1 |
| [PAC Manager](#pac-manager) | 2 |
| [Device Onboarding](#device-onboarding) | 8 |
| [License and Certificate Management](#license-and-certificate-management) | 14 |
| [Device Groups](#device-groups) | 5 |
| [Device Operations](#device-operations) | 7 |
| [Device Resources](#device-resources) | 7 |
| [MNHA Clusters](#mnha-clusters) | 2 |
| [Templates](#templates) | 20 |
| [Device](#device) | 1 |
| [RMA](#rma) | 6 |
| [L2 Cluster Deployments](#l2-cluster-deployments) | 8 |
| [AamwProfile](#aamwprofile) | 5 |
| [ContentFilteringProfile](#contentfilteringprofile) | 5 |
| [ContentSecurityProfile](#contentsecurityprofile) | 5 |
| [ContentSecuritySettings](#contentsecuritysettings) | 2 |
| [EnhancedContentFilteringProfile](#enhancedcontentfilteringprofile) | 5 |
| [EnhancedContentFilteringProfileSet](#enhancedcontentfilteringprofileset) | 8 |
| [DeviceGlobalSettings](#deviceglobalsettings) | 5 |
| [GlobalProfile](#globalprofile) | 2 |
| [GlobalSettings](#globalsettings) | 2 |
| [IPSSignature](#ipssignature) | 7 |
| [IpsProfile](#ipsprofile) | 5 |
| [IPSExemptRule](#ipsexemptrule) | 5 |
| [IPSRule](#ipsrule) | 5 |
| [RuleOption](#ruleoption) | 5 |
| [SecintelProfile](#secintelprofile) | 5 |
| [SSLProxyProfile](#sslproxyprofile) | 5 |
| [WebFilteringProfile](#webfilteringprofile) | 5 |
| [Address](#address) | 5 |
| [AntiSpamProfile](#antispamprofile) | 5 |
| [AntiVirusProfile](#antivirusprofile) | 5 |
| [Application](#application) | 5 |
| [FlowBasedAntivirusProfile](#flowbasedantivirusprofile) | 5 |
| [IcapProfile](#icapprofile) | 5 |
| [IcapServer](#icapserver) | 5 |
| [IdentityObject](#identityobject) | 5 |
| [IpsContext](#ipscontext) | 2 |
| [IpsService](#ipsservice) | 2 |
| [IpsVulnerability](#ipsvulnerability) | 2 |
| [ProxyServer](#proxyserver) | 5 |
| [RedirectProfile](#redirectprofile) | 5 |
| [Scheduler](#scheduler) | 5 |
| [SecintelProfileGroup](#secintelprofilegroup) | 5 |
| [Services](#services) | 5 |
| [SSLInitiation](#sslinitiation) | 5 |
| [SWPProfile](#swpprofile) | 5 |
| [URLCategoryList](#urlcategorylist) | 5 |
| [URLPatterns](#urlpatterns) | 5 |
| [VariableZone](#variablezone) | 5 |
| [Policy Cleanup](#policy-cleanup) | 5 |
| [Policy Deploy](#policy-deploy) | 5 |
| [Firewall Policies](#firewall-policies) | 23 |
| [Policy Assignment](#policy-assignment) | 4 |
| [Policy Preview](#policy-preview) | 5 |
| [Policy Selective Deploy](#policy-selective-deploy) | 5 |
| [Policy State](#policy-state) | 2 |
| [Device Image Definitions](#device-image-definitions) | 8 |
| [NAT Pools](#nat-pools) | 5 |
| [NAT Policies](#nat-policies) | 24 |
| [Subscriptions](#subscriptions) | 3 |

## IAM

| Method | Path | Operation |
|---|---|---|
| `POST` | `/api/v2/change-password` | ChangePassword |
| `GET` | `/api/v2/role/{ID}` | GetRole |
| `GET` | `/api/v2/roles` | ListRoles |
| `POST` | `/api/v2/send-activate-user-email` | SendActivateUserEmail |
| `GET` | `/api/v2/tenant/tenant-id` | GetTokenScope |
| `POST` | `/api/v2/user` | CreateUser |
| `GET` | `/api/v2/user/{user_id}` | GetUser |
| `PUT` | `/api/v2/user/{user_id}` | EditUser |
| `DELETE` | `/api/v2/user/{uuid}` | DeleteUser |
| `GET` | `/api/v2/users` | ListUsers |

## Site Management

| Method | Path | Operation |
|---|---|---|
| `POST` | `/api/v2/bulk_site` | CreateBulkSite |
| `GET` | `/api/v2/external-probe` | GetExternalProbe |
| `DELETE` | `/api/v2/external-probe` | DeleteExternalProbe |
| `POST` | `/api/v2/external-probe` | CreateExternalProbe |
| `POST` | `/api/v2/ipsec-profile` | CreateIpsecProfile |
| `GET` | `/api/v2/ipsec-profile/{profile_name}` | GetIpsecProfile |
| `DELETE` | `/api/v2/ipsec-profile/{profile_name}` | DeleteIpsecProfile |
| `PUT` | `/api/v2/ipsec-profile/{profile_name}` | UpdateIpsecProfile |
| `GET` | `/api/v2/ipsec-profiles` | GetIpsecProfileList |
| `POST` | `/api/v2/site` | CreateSite |
| `POST` | `/api/v2/site/prevalidate` | ValidateSiteParams |
| `GET` | `/api/v2/site/{site_name}` | GetSite |
| `DELETE` | `/api/v2/site/{site_name}` | DeleteSite |
| `PUT` | `/api/v2/site/{site_name}` | UpdateSite |
| `POST` | `/api/v2/site/{site_name}/deploy` | DeploySite |
| `GET` | `/api/v2/sites` | GetSiteList |
| `GET` | `/api/v2/tunnel/{tunnel_id}` | GetTunnel |
| `GET` | `/api/v2/tunnels` | ListTunnels |
| `GET` | `/api/v2/tunnels/status/count` | TunnelCount |
| `GET` | `/api/v2/{tenant_pop_id}/users/count` | GetUsersTenantPop |

## Service Location Management

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v2/tenant-pops` | GetTenantPopList |

## PAC Manager

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v2/pac-file/{name}` | GetPacFile |
| `GET` | `/api/v2/pac-files` | ListPacFiles |

## Device Onboarding

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/devices` | ListDevices |
| `POST` | `/api/v1/devices/create` | BulkCreateDevice |
| `POST` | `/api/v1/devices/remove` | BulkRemoveDevices |
| `GET` | `/api/v1/devices/remove/{remove_id}` | GetRemoveDeviceStatus |
| `GET` | `/api/v1/devices/{device_uuid}` | GetDevice |
| `POST` | `/api/v1/devices/{device_uuid}/get_bootstrap_config` | GetBootstrapConfig |
| `GET` | `/api/v1/proxy_server_config` | GetProxyServerConfig |
| `PUT` | `/api/v1/proxy_server_config` | SetProxyServerConfig |

## License and Certificate Management

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/devices/ca_certificates` | ListCaCertificates |
| `GET` | `/api/v1/devices/delete_certificate/{delete_certificate_id}` | GetDeleteCertificateStatus |
| `GET` | `/api/v1/devices/install_ca_certificate/{install_ca_certificate_id}` | GetInstallCaCertificateStatus |
| `GET` | `/api/v1/devices/install_license/{install_license_id}` | GetInstallLicenseStatus |
| `GET` | `/api/v1/devices/install_local_certificate/{install_local_certificate_id}` | GetInstallLocalCertificateStatus |
| `GET` | `/api/v1/devices/local_certificates` | ListLocalCertificates |
| `GET` | `/api/v1/devices/{device_uuid}/ca_certificates` | ListDeviceCaCertificates |
| `POST` | `/api/v1/devices/{device_uuid}/delete_certificate` | DeleteCertificate |
| `POST` | `/api/v1/devices/{device_uuid}/install_ca_certificate` | InstallCaCertificate |
| `POST` | `/api/v1/devices/{device_uuid}/install_license` | InstallLicense |
| `POST` | `/api/v1/devices/{device_uuid}/install_local_certificate` | InstallLocalCertificate |
| `GET` | `/api/v1/devices/{device_uuid}/licenses` | ListLicenses |
| `GET` | `/api/v1/devices/{device_uuid}/licenses/{license_uuid}` | GetLicense |
| `GET` | `/api/v1/devices/{device_uuid}/local_certificates` | ListDeviceLocalCertificates |

## Device Groups

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/device_groups` | ListDeviceGroups |
| `POST` | `/api/v1/device_groups` | CreateDeviceGroup |
| `GET` | `/api/v1/device_groups/{uuid}` | GetDeviceGroup |
| `DELETE` | `/api/v1/device_groups/{uuid}` | DeleteDeviceGroup |
| `PUT` | `/api/v1/device_groups/{uuid}` | UpdateDeviceGroup |

## Device Operations

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/devices/config/rollback/{config_rollback_id}` | GetRollbackConfigVersionStatus |
| `POST` | `/api/v1/devices/reboot` | BulkRebootDevices |
| `GET` | `/api/v1/devices/reboot/{reboot_id}` | GetRebootStatus |
| `POST` | `/api/v1/devices/sync` | BulkSyncDevices |
| `GET` | `/api/v1/devices/sync/{sync_id}` | GetSyncStatus |
| `GET` | `/api/v1/devices/{device_uuid}/config/versions` | ListConfigVersions |
| `POST` | `/api/v1/devices/{device_uuid}/config/versions/{version_number}/rollback` | RollbackConfigVersion |

## Device Resources

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/devices/{device_uuid}/config/idp_sensors` | GetDeviceConfigIdpSensor |
| `GET` | `/api/v1/devices/{device_uuid}/config/interfaces` | GetDeviceConfigInterface |
| `GET` | `/api/v1/devices/{device_uuid}/config/interfaces/{interface_name}/subinterfaces` | GetDeviceInterfaceSubinterfaces |
| `GET` | `/api/v1/devices/{device_uuid}/config/latest_version` | GetDeviceConfigRevisions |
| `GET` | `/api/v1/devices/{device_uuid}/config/routing_instances` | GetDeviceConfigRI |
| `GET` | `/api/v1/devices/{device_uuid}/config/subinterfaces` | GetDeviceConfigSubInterface |
| `GET` | `/api/v1/devices/{device_uuid}/config/zones` | GetDeviceConfigZones |

## MNHA Clusters

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/mnha_clusters/sync/{mnha_sync_id}` | GetSyncMNHAStatus |
| `POST` | `/api/v1/mnha_clusters/{mnha_cluster_id}/sync` | SyncMnhaDevices |

## Templates

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/templates` | ListTemplates |
| `GET` | `/api/v1/templates/deploy/{deploy_id}` | GetTemplateDeployStatus |
| `GET` | `/api/v1/templates/deploy/{deploy_id}/devices/{device_id}` | GetTemplateDeployResultByDevice |
| `GET` | `/api/v1/templates/preview/{preview_id}` | GetTemplatePreviewStatus |
| `GET` | `/api/v1/templates/preview/{preview_id}/devices/{device_id}` | GetTemplatePreviewResultByDevice |
| `GET` | `/api/v1/templates/validate/{validate_id}` | GetTemplateValidateStatus |
| `GET` | `/api/v1/templates/validate/{validate_id}/devices/{device_id}` | GetTemplateValidateResultByDevice |
| `POST` | `/api/v1/templates/workflow_definitions` | UploadTemplateDefinition |
| `GET` | `/api/v1/templates/{template_id}` | GetTemplate |
| `DELETE` | `/api/v1/templates/{template_id}` | DeleteTemplate |
| `POST` | `/api/v1/templates/{template_id}/csv/download` | DownloadCSVTemplate |
| `POST` | `/api/v1/templates/{template_id}/csv/upload` | UploadCSVTemplate |
| `POST` | `/api/v1/templates/{template_id}/deploy` | DeployTemplate |
| `POST` | `/api/v1/templates/{template_id}/mappings/batch` | BulkSaveTemplateMappings |
| `GET` | `/api/v1/templates/{template_id}/mappings/devices` | ListTemplateMappings |
| `GET` | `/api/v1/templates/{template_id}/mappings/devices/{device_id}` | GetTemplateMapping |
| `DELETE` | `/api/v1/templates/{template_id}/mappings/devices/{device_id}` | DeleteTemplateMapping |
| `PUT` | `/api/v1/templates/{template_id}/mappings/devices/{device_id}` | UpdateTemplateMapping |
| `POST` | `/api/v1/templates/{template_id}/preview` | PreviewTemplate |
| `POST` | `/api/v1/templates/{template_id}/validate` | ValidateTemplate |

## Device

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/device_operations/{device_id}/cluster_interface_status` | GetClusterInterfaceStatusInformation |

## RMA

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/devices/rma/reactivate/{reactivation_id}` | GetReactivationStatus |
| `POST` | `/api/v1/devices/{device_id}/rma/activate` | PutDeviceInRMA |
| `POST` | `/api/v1/devices/{device_id}/rma/reactivate` | ReactivateRMADevice |
| `GET` | `/api/v1/devices/{device_id}/rma/reactivation_config` | GetRMAReactivationConfig |
| `POST` | `/api/v1/devices/{device_id}/rma/reactivation_preferences` | SetupRmaDeviceForReactivation |
| `GET` | `/api/v1/devices/{device_id}/rma/state` | GetRMADeviceStatus |

## L2 Cluster Deployments

| Method | Path | Operation |
|---|---|---|
| `POST` | `/api/v1/l2_cluster_deployments` | CreateL2ClusterDeployment |
| `POST` | `/api/v1/l2_cluster_deployments/validate` | ValidateL2ClusterDeployment |
| `GET` | `/api/v1/l2_cluster_deployments/{l2_cluster_deployment_id}` | GetL2ClusterDeployment |
| `DELETE` | `/api/v1/l2_cluster_deployments/{l2_cluster_deployment_id}` | DeleteL2ClusterDeployment |
| `PUT` | `/api/v1/l2_cluster_deployments/{l2_cluster_deployment_id}` | UpdateL2ClusterDeployment |
| `POST` | `/api/v1/l2_cluster_deployments/{l2_cluster_deployment_id}/deploy` | CommitL2ClusterDeployment |
| `GET` | `/api/v1/l2_cluster_deployments/{l2_cluster_deployment_id}/status` | GetL2ClusterDeploymentStatus |
| `GET` | `/api/v1/l2_cluster_model_config` | GetL2ClusterModelConfig |

## AamwProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/aamw_profiles` | ListAamwProfile |
| `POST` | `/api/v1/aamw_profiles` | CreateAamwProfile |
| `GET` | `/api/v1/aamw_profiles/{uuid}` | GetAamwProfile |
| `DELETE` | `/api/v1/aamw_profiles/{uuid}` | DeleteAamwProfile |
| `PUT` | `/api/v1/aamw_profiles/{uuid}` | UpdateAamwProfile |

## ContentFilteringProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/content_filtering_profiles` | ListContentFilteringProfile |
| `POST` | `/api/v1/content_filtering_profiles` | CreateContentFilteringProfile |
| `GET` | `/api/v1/content_filtering_profiles/{uuid}` | GetContentFilteringProfile |
| `DELETE` | `/api/v1/content_filtering_profiles/{uuid}` | DeleteContentFilteringProfile |
| `PUT` | `/api/v1/content_filtering_profiles/{uuid}` | UpdateContentFilteringProfile |

## ContentSecurityProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/content_security_profiles` | ListContentSecurityProfile |
| `POST` | `/api/v1/content_security_profiles` | CreateContentSecurityProfile |
| `GET` | `/api/v1/content_security_profiles/{uuid}` | GetContentSecurityProfile |
| `DELETE` | `/api/v1/content_security_profiles/{uuid}` | DeleteContentSecurityProfile |
| `PUT` | `/api/v1/content_security_profiles/{uuid}` | UpdateContentSecurityProfile |

## ContentSecuritySettings

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/content_security_settings` | GetContentSecuritySettings |
| `PUT` | `/api/v1/content_security_settings` | UpdateContentSecuritySettings |

## EnhancedContentFilteringProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/enhanced_content_filtering_profiles` | ListEnhancedContentFilteringProfile |
| `POST` | `/api/v1/enhanced_content_filtering_profiles` | CreateEnhancedContentFilteringProfile |
| `GET` | `/api/v1/enhanced_content_filtering_profiles/{uuid}` | GetEnhancedContentFilteringProfile |
| `DELETE` | `/api/v1/enhanced_content_filtering_profiles/{uuid}` | DeleteEnhancedContentFilteringProfile |
| `PUT` | `/api/v1/enhanced_content_filtering_profiles/{uuid}` | UpdateEnhancedContentFilteringProfile |

## EnhancedContentFilteringProfileSet

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets` | ListEnhancedContentFilteringProfileRuleSet |
| `POST` | `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets` | CreateEnhancedContentFilteringProfileRuleSet |
| `GET` | `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets/{rule_set_uuid}/rules` | ListEnhancedContentFilteringProfileRule |
| `POST` | `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets/{rule_set_uuid}/rules` | CreateEnhancedContentFilteringProfileRule |
| `GET` | `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets/{rule_set_uuid}/rules/{uuid}` | GetEnhancedContentFilteringProfileRule |
| `DELETE` | `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets/{rule_set_uuid}/rules/{uuid}` | DeleteEnhancedContentFilteringProfileRule |
| `PUT` | `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets/{rule_set_uuid}/rules/{uuid}` | UpdateEnhancedContentFilteringProfileRule |
| `DELETE` | `/api/v1/enhanced_content_filtering_profiles/{profile_uuid}/rule_sets/{uuid}` | DeleteEnhancedContentFilteringProfileRuleSet |

## DeviceGlobalSettings

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/firewall_device_global_settings` | ListDeviceGlobalSettings |
| `POST` | `/api/v1/firewall_device_global_settings` | CreateDeviceGlobalSettings |
| `GET` | `/api/v1/firewall_device_global_settings/{uuid}` | GetDeviceGlobalSettings |
| `DELETE` | `/api/v1/firewall_device_global_settings/{uuid}` | DeleteDeviceGlobalSettings |
| `PUT` | `/api/v1/firewall_device_global_settings/{uuid}` | UpdateDeviceGlobalSettings |

## GlobalProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/firewall_global_profiles` | GetGlobalProfile |
| `PUT` | `/api/v1/firewall_global_profiles` | UpdateGlobalProfile |

## GlobalSettings

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/firewall_global_settings` | GetGlobalSettings |
| `PUT` | `/api/v1/firewall_global_settings` | UpdateGlobalSettings |

## IPSSignature

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ips_anomaly_tests` | ListAnomalyTests |
| `GET` | `/api/v1/ips_signature_categories` | ListSignatureCategories |
| `GET` | `/api/v1/ips_signatures` | ListIpsSignature |
| `POST` | `/api/v1/ips_signatures` | CreateIpsSignature |
| `GET` | `/api/v1/ips_signatures/{uuid}` | GetIpsSignature |
| `DELETE` | `/api/v1/ips_signatures/{uuid}` | DeleteIpsSignature |
| `PUT` | `/api/v1/ips_signatures/{uuid}` | UpdateIpsSignature |

## IpsProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ips_profiles` | ListIpsProfile |
| `POST` | `/api/v1/ips_profiles` | CreateIpsProfile |
| `DELETE` | `/api/v1/ips_profiles/{uuid}` | DeleteIpsProfile |
| `GET` | `/api/v1/ips_profiles/{uuid}` | GetIpsProfile |
| `PUT` | `/api/v1/ips_profiles/{uuid}` | UpdateIpsProfile |

## IPSExemptRule

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ips_profiles/{profile_uuid}/exempt_rules` | ListIPSExemptRule |
| `POST` | `/api/v1/ips_profiles/{profile_uuid}/exempt_rules` | CreateIPSExemptRule |
| `GET` | `/api/v1/ips_profiles/{profile_uuid}/exempt_rules/{rule_uuid}` | GetIPSExemptRule |
| `DELETE` | `/api/v1/ips_profiles/{profile_uuid}/exempt_rules/{rule_uuid}` | DeleteIPSExemptRule |
| `PUT` | `/api/v1/ips_profiles/{profile_uuid}/exempt_rules/{rule_uuid}` | UpdateIPSExemptRule |

## IPSRule

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ips_profiles/{profile_uuid}/ips_rules` | ListIPSRule |
| `POST` | `/api/v1/ips_profiles/{profile_uuid}/ips_rules` | CreateIPSRule |
| `GET` | `/api/v1/ips_profiles/{profile_uuid}/ips_rules/{rule_uuid}` | GetIPSRule |
| `DELETE` | `/api/v1/ips_profiles/{profile_uuid}/ips_rules/{rule_uuid}` | DeleteIPSRule |
| `PUT` | `/api/v1/ips_profiles/{profile_uuid}/ips_rules/{rule_uuid}` | UpdateIPSRule |

## RuleOption

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/rule_options` | ListRuleOption |
| `POST` | `/api/v1/rule_options` | CreateRuleOption |
| `GET` | `/api/v1/rule_options/{uuid}` | GetRuleOption |
| `DELETE` | `/api/v1/rule_options/{uuid}` | DeleteRuleOption |
| `PUT` | `/api/v1/rule_options/{uuid}` | UpdateRuleOption |

## SecintelProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/secintel_profiles` | ListSecIntelProfile |
| `POST` | `/api/v1/secintel_profiles` | CreateSecintelProfile |
| `GET` | `/api/v1/secintel_profiles/{uuid}` | GetSecintelProfile |
| `DELETE` | `/api/v1/secintel_profiles/{uuid}` | DeleteSecintelProfile |
| `PUT` | `/api/v1/secintel_profiles/{uuid}` | UpdateSecintelProfile |

## SSLProxyProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ssl_proxy_profiles` | ListSSLProxyProfile |
| `POST` | `/api/v1/ssl_proxy_profiles` | CreateSSLProxyProfile |
| `GET` | `/api/v1/ssl_proxy_profiles/{uuid}` | GetSSLProxyProfile |
| `DELETE` | `/api/v1/ssl_proxy_profiles/{uuid}` | DeleteSSLProxyProfile |
| `PUT` | `/api/v1/ssl_proxy_profiles/{uuid}` | UpdateSSLProxyProfile |

## WebFilteringProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/web_filtering_profiles` | ListWebFilteringProfile |
| `POST` | `/api/v1/web_filtering_profiles` | CreateWebFilteringProfile |
| `GET` | `/api/v1/web_filtering_profiles/{uuid}` | GetWebFilteringProfile |
| `DELETE` | `/api/v1/web_filtering_profiles/{uuid}` | DeleteWebFilteringProfile |
| `PUT` | `/api/v1/web_filtering_profiles/{uuid}` | UpdateWebFilteringProfile |

## Address

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/addresses` | ListAddress |
| `POST` | `/api/v1/addresses` | CreateAddress |
| `GET` | `/api/v1/addresses/{uuid}` | GetAddress |
| `DELETE` | `/api/v1/addresses/{uuid}` | DeleteAddress |
| `PUT` | `/api/v1/addresses/{uuid}` | UpdateAddress |

## AntiSpamProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/anti_spam_profiles` | ListAntiSpamProfile |
| `POST` | `/api/v1/anti_spam_profiles` | CreateAntiSpamProfile |
| `GET` | `/api/v1/anti_spam_profiles/{uuid}` | GetAntiSpamProfile |
| `DELETE` | `/api/v1/anti_spam_profiles/{uuid}` | DeleteAntiSpamProfile |
| `PUT` | `/api/v1/anti_spam_profiles/{uuid}` | UpdateAntiSpamProfile |

## AntiVirusProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/anti_virus_profiles` | ListAntiVirusProfile |
| `POST` | `/api/v1/anti_virus_profiles` | CreateAntiVirusProfile |
| `GET` | `/api/v1/anti_virus_profiles/{uuid}` | GetAntiVirusProfile |
| `DELETE` | `/api/v1/anti_virus_profiles/{uuid}` | DeleteAntiVirusProfile |
| `PUT` | `/api/v1/anti_virus_profiles/{uuid}` | UpdateAntiVirusProfile |

## Application

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/applications` | ListApplication |
| `POST` | `/api/v1/applications` | CreateApplication |
| `GET` | `/api/v1/applications/{uuid}` | GetApplication |
| `DELETE` | `/api/v1/applications/{uuid}` | DeleteApplication |
| `PUT` | `/api/v1/applications/{uuid}` | UpdateApplication |

## FlowBasedAntivirusProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/flow_based_antivirus_profiles` | ListFlowBasedAntivirusProfile |
| `POST` | `/api/v1/flow_based_antivirus_profiles` | CreateFlowBasedAntivirusProfile |
| `GET` | `/api/v1/flow_based_antivirus_profiles/{uuid}` | GetFlowBasedAntivirusProfile |
| `DELETE` | `/api/v1/flow_based_antivirus_profiles/{uuid}` | DeleteFlowBasedAntivirusProfile |
| `PUT` | `/api/v1/flow_based_antivirus_profiles/{uuid}` | UpdateFlowBasedAntivirusProfile |

## IcapProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/icap_profiles` | ListIcapProfile |
| `POST` | `/api/v1/icap_profiles` | CreateIcapProfile |
| `GET` | `/api/v1/icap_profiles/{uuid}` | GetIcapProfile |
| `DELETE` | `/api/v1/icap_profiles/{uuid}` | DeleteIcapProfile |
| `PUT` | `/api/v1/icap_profiles/{uuid}` | UpdateIcapProfile |

## IcapServer

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/icap_servers` | ListIcapServer |
| `POST` | `/api/v1/icap_servers` | CreateIcapServer |
| `GET` | `/api/v1/icap_servers/{uuid}` | GetIcapServer |
| `DELETE` | `/api/v1/icap_servers/{uuid}` | DeleteIcapServer |
| `PUT` | `/api/v1/icap_servers/{uuid}` | UpdateIcapServer |

## IdentityObject

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/identity_objects` | ListIdentityObject |
| `POST` | `/api/v1/identity_objects` | CreateIdentityObject |
| `GET` | `/api/v1/identity_objects/{uuid}` | GetIdentityObject |
| `DELETE` | `/api/v1/identity_objects/{uuid}` | DeleteIdentityObject |
| `PUT` | `/api/v1/identity_objects/{uuid}` | UpdateIdentityObject |

## IpsContext

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ips_contexts` | ListIpsContext |
| `GET` | `/api/v1/ips_contexts/{uuid}` | GetIpsContext |

## IpsService

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ips_services` | ListIpsService |
| `GET` | `/api/v1/ips_services/{uuid}` | GetIpsService |

## IpsVulnerability

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ips_vulnerabilities` | ListIpsVulnerability |
| `GET` | `/api/v1/ips_vulnerabilities/{uuid}` | GetIpsVulnerability |

## ProxyServer

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/proxy_servers` | ListProxyServer |
| `POST` | `/api/v1/proxy_servers` | CreateProxyServer |
| `GET` | `/api/v1/proxy_servers/{uuid}` | GetProxyServer |
| `DELETE` | `/api/v1/proxy_servers/{uuid}` | DeleteProxyServer |
| `PUT` | `/api/v1/proxy_servers/{uuid}` | UpdateProxyServer |

## RedirectProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/redirect_profiles` | ListRedirectProfile |
| `POST` | `/api/v1/redirect_profiles` | CreateRedirectProfile |
| `GET` | `/api/v1/redirect_profiles/{uuid}` | GetRedirectProfile |
| `DELETE` | `/api/v1/redirect_profiles/{uuid}` | DeleteRedirectProfile |
| `PUT` | `/api/v1/redirect_profiles/{uuid}` | UpdateRedirectProfile |

## Scheduler

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/schedulers` | ListScheduler |
| `POST` | `/api/v1/schedulers` | CreateScheduler |
| `GET` | `/api/v1/schedulers/{uuid}` | GetScheduler |
| `DELETE` | `/api/v1/schedulers/{uuid}` | DeleteScheduler |
| `PUT` | `/api/v1/schedulers/{uuid}` | UpdateScheduler |

## SecintelProfileGroup

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/secintel_profiles_groups` | ListSecintelProfileGroup |
| `POST` | `/api/v1/secintel_profiles_groups` | CreateSecintelProfileGroup |
| `GET` | `/api/v1/secintel_profiles_groups/{uuid}` | GetSecintelProfileGroup |
| `DELETE` | `/api/v1/secintel_profiles_groups/{uuid}` | DeleteSecintelProfileGroup |
| `PUT` | `/api/v1/secintel_profiles_groups/{uuid}` | UpdateSecintelProfileGroup |

## Services

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/services` | ListServices |
| `POST` | `/api/v1/services` | CreateServices |
| `GET` | `/api/v1/services/{uuid}` | GetServices |
| `DELETE` | `/api/v1/services/{uuid}` | DeleteServices |
| `PUT` | `/api/v1/services/{uuid}` | UpdateServices |

## SSLInitiation

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/ssl_initiations` | ListSSLInitiation |
| `POST` | `/api/v1/ssl_initiations` | CreateSSLInitiation |
| `GET` | `/api/v1/ssl_initiations/{uuid}` | GetSSLInitiation |
| `DELETE` | `/api/v1/ssl_initiations/{uuid}` | DeleteSSLInitiation |
| `PUT` | `/api/v1/ssl_initiations/{uuid}` | UpdateSSLInitiation |

## SWPProfile

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/swp_profiles` | ListSWPProfile |
| `POST` | `/api/v1/swp_profiles` | CreateSWPProfile |
| `GET` | `/api/v1/swp_profiles/{uuid}` | GetSWPProfile |
| `DELETE` | `/api/v1/swp_profiles/{uuid}` | DeleteSWPProfile |
| `PUT` | `/api/v1/swp_profiles/{uuid}` | UpdateSWPProfile |

## URLCategoryList

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/url_category_lists` | ListURLCategoryList |
| `POST` | `/api/v1/url_category_lists` | CreateURLCategoryList |
| `GET` | `/api/v1/url_category_lists/{uuid}` | GetURLCategoryList |
| `DELETE` | `/api/v1/url_category_lists/{uuid}` | DeleteURLCategoryList |
| `PUT` | `/api/v1/url_category_lists/{uuid}` | UpdateURLCategoryList |

## URLPatterns

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/url_patterns` | ListURLPatterns |
| `POST` | `/api/v1/url_patterns` | CreateURLPatterns |
| `GET` | `/api/v1/url_patterns/{uuid}` | GetURLPatterns |
| `DELETE` | `/api/v1/url_patterns/{uuid}` | DeleteURLPatterns |
| `PUT` | `/api/v1/url_patterns/{uuid}` | UpdateURLPatterns |

## VariableZone

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/variable_zones` | ListVariableZone |
| `POST` | `/api/v1/variable_zones` | CreateVariableZone |
| `GET` | `/api/v1/variable_zones/{uuid}` | GetVariableZone |
| `DELETE` | `/api/v1/variable_zones/{uuid}` | DeleteVariableZone |
| `PUT` | `/api/v1/variable_zones/{uuid}` | UpdateVariableZone |

## Policy Cleanup

| Method | Path | Operation |
|---|---|---|
| `POST` | `/api/v1/policies/cleanup` | CleanupMultiplePolicies |
| `GET` | `/api/v1/policies/cleanup/{cleanup_id}` | GetPolicyCleanupStatus |
| `GET` | `/api/v1/policies/cleanup/{cleanup_id}/devices/{device_id}` | GetPolicyCleanupResultByDevice |
| `POST` | `/api/v1/policies/firewall/{policy_id}/cleanup` | CleanupSingleFirewallPolicy |
| `POST` | `/api/v1/policies/nat/{policy_id}/cleanup` | CleanupSingleNatPolicy |

## Policy Deploy

| Method | Path | Operation |
|---|---|---|
| `POST` | `/api/v1/policies/deploy` | DeployMultiplePolicies |
| `GET` | `/api/v1/policies/deploy/{deploy_id}` | GetPolicyDeployStatus |
| `GET` | `/api/v1/policies/deploy/{deploy_id}/devices/{device_id}` | GetPolicyDeployResultByDevice |
| `POST` | `/api/v1/policies/firewall/{policy_id}/deploy` | DeploySingleFirewallPolicy |
| `POST` | `/api/v1/policies/nat/{policy_id}/deploy` | DeploySingleNatPolicy |

## Firewall Policies

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/policies/firewall` | ListFirewallPolicies |
| `POST` | `/api/v1/policies/firewall` | CreateFirewallPolicies |
| `GET` | `/api/v1/policies/firewall/{policy_uuid}` | GetFirewallPolicies |
| `DELETE` | `/api/v1/policies/firewall/{policy_uuid}` | DeleteFirewallPolicies |
| `PUT` | `/api/v1/policies/firewall/{policy_uuid}` | UpdateFirewallPolicies |
| `GET` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/heirarchy` | ListFirewallPolicyHeirarchy |
| `POST` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/move_rules` | BulkMoveFirewallPolicyRules |
| `GET` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups` | ListFirewallPolicyRuleGroups |
| `POST` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups` | CreateFirewallPolicyRuleGroup |
| `GET` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}` | GetFirewallPolicyRuleGroup |
| `DELETE` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}` | DeleteFirewallPolicyRuleGroup |
| `PUT` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}` | UpdateFirewallPolicyRuleGroup |
| `GET` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}/rules` | ListFirewallPolicyRulesInGroup |
| `POST` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}/rules` | CreateFirewallPolicyRuleInGroup |
| `GET` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}/rules/{rule_uuid}` | GetFirewallPolicyRuleInGroup |
| `DELETE` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}/rules/{rule_uuid}` | DeleteFirewallPolicyRuleInGroup |
| `PUT` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}/rules/{rule_uuid}` | UpdateFirewallPolicyRuleInGroup |
| `POST` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rule_groups/{group_uuid}/rules/{rule_uuid}/move` | MoveFirewallPolicyRulesInGroup |
| `GET` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rules` | ListFirewallPolicyRules |
| `POST` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rules` | CreateFirewallPolicyRule |
| `GET` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rules/{rule_uuid}` | GetFirewallPolicyRule |
| `DELETE` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rules/{rule_uuid}` | DeleteFirewallPolicyRule |
| `PUT` | `/api/v1/policies/firewall/{policy_uuid}/{scope}/rules/{rule_uuid}` | UpdateFirewallPolicyRule |

## Policy Assignment

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/policies/firewall/{policy_id}/assignments` | ListFirewallPolicyAssignments |
| `POST` | `/api/v1/policies/firewall/{policy_id}/assignments/batch` | BatchFirewallPolicyAssignments |
| `GET` | `/api/v1/policies/nat/{policy_id}/assignments` | ListNatPolicyAssignments |
| `POST` | `/api/v1/policies/nat/{policy_id}/assignments/batch` | BatchNatPolicyAssignments |

## Policy Preview

| Method | Path | Operation |
|---|---|---|
| `POST` | `/api/v1/policies/firewall/{policy_id}/preview` | PreviewSingleFirewallPolicy |
| `POST` | `/api/v1/policies/nat/{policy_id}/preview` | PreviewSingleNatPolicy |
| `POST` | `/api/v1/policies/preview` | PreviewMultiplePolicies |
| `GET` | `/api/v1/policies/preview/{preview_id}` | GetPolicyPreviewStatus |
| `GET` | `/api/v1/policies/preview/{preview_id}/devices/{device_id}` | GetPolicyPreviewResultByDevice |

## Policy Selective Deploy

| Method | Path | Operation |
|---|---|---|
| `POST` | `/api/v1/policies/firewall/{policy_id}/selective_deploy` | SelectiveDeploySingleFirewallPolicy |
| `POST` | `/api/v1/policies/nat/{policy_id}/selective_deploy` | SelectiveDeploySingleNatPolicy |
| `POST` | `/api/v1/policies/selective_deploy` | SelectiveDeployMultiplePolicies |
| `GET` | `/api/v1/policies/selective_deploy/{selective_deploy_id}` | GetPolicySelectiveDeployStatus |
| `GET` | `/api/v1/policies/selective_deploy/{selective_deploy_id}/devices/{device_id}` | GetPolicySelectiveDeployResultByDevice |

## Policy State

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/policies/firewall/{policy_uuid}/state` | GetFirewallPolicyState |
| `GET` | `/api/v1/policies/nat/{policy_id}/state` | GetNATPolicyState |

## Device Image Definitions

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/device_image_definitions` | ListDeviceImageDefinitions |
| `POST` | `/api/v1/device_image_definitions` | CreateDeviceImageDefinition |
| `POST` | `/api/v1/device_image_definitions/deploy_image` | BulkDeployImage |
| `GET` | `/api/v1/device_image_definitions/deploy_image/{deploy_image_id}` | GetDeployImageStatus |
| `GET` | `/api/v1/device_image_definitions/stage_image/{stage_image_id}` | GetStageImageStatus |
| `POST` | `/api/v1/device_image_definitions/{image_uuid}/deploy_image` | DeployImage |
| `POST` | `/api/v1/device_image_definitions/{image_uuid}/stage_image` | StageImage |
| `DELETE` | `/api/v1/device_image_definitions/{uuid}` | DeleteDeviceImageDefinition |

## NAT Pools

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/nat_pools` | ListNatPools |
| `POST` | `/api/v1/nat_pools` | CreateNatPool |
| `GET` | `/api/v1/nat_pools/{pool_id}` | GetNatPool |
| `DELETE` | `/api/v1/nat_pools/{pool_id}` | DeleteNatPool |
| `PUT` | `/api/v1/nat_pools/{pool_id}` | UpdateNatPool |

## NAT Policies

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/policies/nat` | ListNatPolicies |
| `POST` | `/api/v1/policies/nat` | CreateNatPolicy |
| `GET` | `/api/v1/policies/nat/{id}` | GetNatPolicy |
| `DELETE` | `/api/v1/policies/nat/{id}` | DeleteNatPolicy |
| `PUT` | `/api/v1/policies/nat/{id}` | UpdateNatPolicy |
| `GET` | `/api/v1/policies/nat/{policy_id}/arp_entries` | GetArpEntries |
| `GET` | `/api/v1/policies/nat/{policy_id}/hierarchy` | ListNatPolicyHierarchy |
| `POST` | `/api/v1/policies/nat/{policy_id}/move_rules` | MoveNatRules |
| `GET` | `/api/v1/policies/nat/{policy_id}/proxy_ndp_entries` | GetProxyNdpEntries |
| `GET` | `/api/v1/policies/nat/{policy_id}/rule_groups` | ListNatRuleGroups |
| `POST` | `/api/v1/policies/nat/{policy_id}/rule_groups` | CreateNatRuleGroup |
| `POST` | `/api/v1/policies/nat/{policy_id}/rule_groups/move` | MoveNatRuleGroups |
| `GET` | `/api/v1/policies/nat/{policy_id}/rule_groups/{group_id}` | GetNatRuleGroup |
| `DELETE` | `/api/v1/policies/nat/{policy_id}/rule_groups/{group_id}` | DeleteNatRuleGroup |
| `GET` | `/api/v1/policies/nat/{policy_id}/rule_groups/{group_id}/rules` | ListNatRulesInGroup |
| `POST` | `/api/v1/policies/nat/{policy_id}/rule_groups/{group_id}/rules` | CreateNatRuleInGroup |
| `GET` | `/api/v1/policies/nat/{policy_id}/rule_groups/{group_id}/rules/{rule_id}` | GetNatRuleInGroup |
| `DELETE` | `/api/v1/policies/nat/{policy_id}/rule_groups/{group_id}/rules/{rule_id}` | DeleteNatRuleInGroup |
| `PUT` | `/api/v1/policies/nat/{policy_id}/rule_groups/{group_id}/rules/{rule_id}` | UpdateNatRuleInGroup |
| `GET` | `/api/v1/policies/nat/{policy_id}/rules` | ListNatRules |
| `POST` | `/api/v1/policies/nat/{policy_id}/rules` | CreateNatRule |
| `GET` | `/api/v1/policies/nat/{policy_id}/rules/{rule_id}` | GetNatRule |
| `DELETE` | `/api/v1/policies/nat/{policy_id}/rules/{rule_id}` | DeleteNatRule |
| `PUT` | `/api/v1/policies/nat/{policy_id}/rules/{rule_id}` | UpdateNatRule |

## Subscriptions

| Method | Path | Operation |
|---|---|---|
| `GET` | `/api/v1/subscriptions` | ListSubscriptions |
| `GET` | `/api/v1/subscriptions/{subscription_uuid}/associations` | ListSubscriptionAssociations |
| `POST` | `/api/v1/subscriptions/{subscription_uuid}/associations/create` | AssociateSubscription |
