//
//  DOMainViewController.m
//  Dopamine
//
//  Created by tomt000 on 08/01/2024.
//

#import "DOMainViewController.h"
#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOJailbreaker.h"
#import "DOGlobalAppearance.h"
#import "DOActionMenuButton.h"
#import "DOUpdateViewController.h"
#import "DOLogCrashViewController.h"
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <os/log.h>
#import <pthread.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <libjailbreak/libjailbreak.h>

@interface DOMainViewController ()

@property DOJailbreakButton *jailbreakBtn;
@property NSArray<NSLayoutConstraint *> *jailbreakButtonConstraints;
@property DOActionMenuButton *updateButton;
@property(nonatomic) BOOL hideStatusBar;
@property(nonatomic) BOOL hideHomeIndicator;

@end

@implementation DOMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupStack];
}

-(void)setupStack
{
    UIStackView *stackView = [[UIStackView alloc] init];
    [stackView setAxis:UILayoutConstraintAxisVertical];
    [stackView setAlignment:UIStackViewAlignmentTrailing];
    [stackView setDistribution:UIStackViewDistributionEqualSpacing];
    [stackView setTranslatesAutoresizingMaskIntoConstraints:NO];

    [self.view addSubview:stackView];


    int statusBarHeight = fmax(15, [[UIApplication sharedApplication] keyWindow].safeAreaInsets.top - 20);

    [NSLayoutConstraint activateConstraints:@[
        [stackView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:statusBarHeight],//-35
        [stackView.heightAnchor constraintEqualToAnchor:self.view.heightAnchor multiplier:[DOGlobalAppearance isHomeButtonDevice] ? 0.78 : 0.73]
    ]];

    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad)
    {
        NSLayoutConstraint *relativeWidthConstraint = [stackView.widthAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.8];
        relativeWidthConstraint.priority = UILayoutPriorityDefaultHigh;
        NSLayoutConstraint *maxWidthConstraint = [stackView.widthAnchor constraintLessThanOrEqualToConstant:UI_IPAD_MAX_WIDTH];
        maxWidthConstraint.priority = UILayoutPriorityRequired;

        [NSLayoutConstraint activateConstraints:@[
            relativeWidthConstraint,
            maxWidthConstraint,
            [stackView.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor]
        ]];
    }
    else
    {
        [NSLayoutConstraint activateConstraints:@[
            [stackView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:UI_PADDING],
            [stackView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-UI_PADDING],
        ]];
    }

    //Header
    DOHeaderView *headerView = [[DOHeaderView alloc] initWithImage: [UIImage imageNamed:@"Dopamine"] subtitles: @[
        [DOGlobalAppearance mainSubtitleString:[[DOEnvironmentManager sharedManager] versionSupportString]],
        [DOGlobalAppearance secondarySubtitleString:DOLocalizedString(@"Credits_Made_By")],
    ]];
    
    [stackView addArrangedSubview:headerView];

    [NSLayoutConstraint activateConstraints:@[
        [headerView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor constant:5],
        [headerView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor]
    ]];
    
    //Action Menu
    DOActionMenuView *actionView = [[DOActionMenuView alloc] initWithActions:@[
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Settings_Title") image:[UIImage systemImageNamed:@"gearshape" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"settings" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOSettingsController alloc] init] animated:YES];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Restart_SpringBoard_Title") image:[UIImage systemImageNamed:@"arrow.clockwise" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"respring" handler:^(__kindof UIAction * _Nonnull action) {
            [self fadeToBlack:^{
                [[DOEnvironmentManager sharedManager] respring];
            }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Reboot_Userspace_Title") image:[UIImage systemImageNamed:@"arrow.clockwise.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"reboot-userspace" handler:^(__kindof UIAction * _Nonnull action) {
            [self fadeToBlack:^{
                [[DOEnvironmentManager sharedManager] rebootUserspace];
            }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Credits_Title") image:[UIImage systemImageNamed:@"info.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"credits" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOCreditsViewController alloc] init] animated:YES];
        }]
    ] delegate:self];
    
    [stackView addArrangedSubview: actionView];

    [NSLayoutConstraint activateConstraints:@[
        [actionView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [actionView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
    ]];
    
    
    UIView *buttonPlaceHolder = [[UIView alloc] init];
    [buttonPlaceHolder setTranslatesAutoresizingMaskIntoConstraints:NO];
    [stackView addArrangedSubview:buttonPlaceHolder];
    [NSLayoutConstraint activateConstraints:@[
        [buttonPlaceHolder.heightAnchor constraintEqualToConstant:60]
    ]];
    
    //Jailbreak Button
    BOOL isJailbroken = [[DOEnvironmentManager sharedManager] isJailbroken] || [[DOEnvironmentManager sharedManager] isJailbrokenWithOtherJailbreak];
    BOOL isSupported = [[DOEnvironmentManager sharedManager] isSupported];
    BOOL isResearchTarget = [[DOEnvironmentManager sharedManager] isA15IOS2601ResearchTarget];

    NSString *jailbreakButtonTitle = [self jailbreakButtonTitle];
        
    UIImage *jailbreakButtonImage;
    if (isResearchTarget)
        jailbreakButtonImage = [UIImage systemImageNamed:@"waveform.path.ecg" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    else if (isSupported)
        jailbreakButtonImage = [UIImage systemImageNamed:@"lock.open" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    else
        jailbreakButtonImage = [UIImage systemImageNamed:@"lock.slash" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    
    self.jailbreakBtn = [[DOJailbreakButton alloc] initWithAction: [UIAction actionWithTitle:jailbreakButtonTitle image:jailbreakButtonImage identifier:@"jailbreak" handler:^(__kindof UIAction * _Nonnull action) {
        [actionView hide];
        [self.jailbreakBtn expandButton: self.jailbreakButtonConstraints];

        self.updateButton.userInteractionEnabled = NO;
        [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0  options: UIViewAnimationOptionCurveEaseInOut animations:^{
            [headerView setTransform:CGAffineTransformMakeTranslation(0, -25)];
            self.updateButton.alpha = 0;
        } completion:nil];
        
        if ([[DOEnvironmentManager sharedManager] isA15IOS2601ResearchTarget]) {
            [self startResearchDiagnostics];
        }
        else {
            [self startJailbreak];
        }
        
    }]];
    self.jailbreakBtn.enabled = !isJailbroken && (isSupported || isResearchTarget);

    [self.view addSubview:self.jailbreakBtn];

    [NSLayoutConstraint activateConstraints:(self.jailbreakButtonConstraints = @[
        [self.jailbreakBtn.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [self.jailbreakBtn.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
        [self.jailbreakBtn.heightAnchor constraintEqualToAnchor:buttonPlaceHolder.heightAnchor],
        [self.jailbreakBtn.centerYAnchor constraintEqualToAnchor:buttonPlaceHolder.centerYAnchor]
    ])];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.1 * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        if ([[DOUIManager sharedInstance] environmentUpdateAvailable])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self setupUpdateAvailable:YES];
            });
        }
        else if ([[DOUIManager sharedInstance] isUpdateAvailable])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self setupUpdateAvailable:NO];
            });
        }
    });
}

- (NSString *)jailbreakButtonTitle
{
    BOOL isJailbroken = [[DOEnvironmentManager sharedManager] isJailbroken];
    BOOL isSupported = [[DOEnvironmentManager sharedManager] isSupported];
    BOOL isResearchTarget = [[DOEnvironmentManager sharedManager] isA15IOS2601ResearchTarget];
    BOOL removeJailbreakEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO];

    NSString *jailbreakButtonTitle = DOLocalizedString(@"Button_Jailbreak_Title");
    if (isResearchTarget)
        jailbreakButtonTitle = DOLocalizedString(@"Research_Button_Run");
    else if (!isSupported)
        jailbreakButtonTitle = DOLocalizedString(@"Unsupported");
    else if (isJailbroken)
        jailbreakButtonTitle = DOLocalizedString(@"Status_Title_Jailbroken");
    else if (removeJailbreakEnabled)
        jailbreakButtonTitle = DOLocalizedString(@"Button_Remove_Jailbreak");
    
    return jailbreakButtonTitle;
}

- (void)emitResearchDiagnosticEvent:(NSString *)event
{
    NSString *line = [NSString stringWithFormat:@"[A15DIAG] %@", event];
    [[DOUIManager sharedInstance] sendLog:line debug:NO];
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "%{public}@", line);
}

- (void)startResearchDiagnostics
{
    DOEnvironmentManager *environment = [DOEnvironmentManager sharedManager];
    if (![environment isA15IOS2601ResearchTarget]) {
        [self emitResearchDiagnosticEvent:@"checkpoint=target.identity status=REJECTED"];
        return;
    }

    [[DOUIManager sharedInstance] startLogCapture];
    self.jailbreakBtn.enabled = NO;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableArray<NSDictionary *> *events = [NSMutableArray new];
        void (^record)(NSString *, NSString *, NSString *) = ^(NSString *checkpoint, NSString *status, NSString *evidence) {
            NSDictionary *event = @{
                @"checkpoint": checkpoint,
                @"status": status,
                @"evidence": evidence,
            };
            [events addObject:event];
            [self emitResearchDiagnosticEvent:[NSString stringWithFormat:@"checkpoint=%@ status=%@ evidence=%@", checkpoint, status, evidence]];
        };

        record(@"target.identity", @"OBSERVED", @"iPhone14,2/A15/iOS-26.0.1/23A355");
        record(@"environment.sptm", @"OBSERVED", [environment isSPTM] ? @"present" : @"not-detected");

        BOOL arm64e = [environment isArm64e];
        BOOL pacRequired = [environment isPACBypassRequired];
        BOOL pplRequired = [environment isPPLBypassRequired];
        record(@"environment.arm64e", arm64e ? @"OBSERVED" : @"UNEXPECTED", arm64e ? @"true" : @"false");
        record(@"environment.pac_bypass", pacRequired ? @"REQUIRED" : @"NOT_REQUIRED", @"DOEnvironmentManager");
        record(@"environment.ppl_bypass", pplRequired ? @"REQUIRED" : @"NOT_REQUIRED", @"DOEnvironmentManager");
        record(@"environment.installation", @"OBSERVED",
               [NSString stringWithFormat:@"mode=%@ uid=%u", [environment isInstalledThroughTrollStore] ? @"trollstore" : @"sideloaded", getuid()]);

        NSString *bundlePath = [NSBundle mainBundle].bundlePath;
        NSString *documentsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        NSString *(^artifactLocation)(NSArray<NSString *> *) = ^NSString *(NSArray<NSString *> *names) {
            for (NSString *name in names) {
                if ([[NSFileManager defaultManager] fileExistsAtPath:[bundlePath stringByAppendingPathComponent:name]]) {
                    return [@"bundle/" stringByAppendingString:name];
                }
                if ([[NSFileManager defaultManager] fileExistsAtPath:[documentsPath stringByAppendingPathComponent:name]]) {
                    return [@"Documents/" stringByAppendingString:name];
                }
            }
            return nil;
        };
        NSDictionary<NSString *, NSArray<NSString *> *> *artifactNames = @{
            @"kernel.static_artifact": @[@"kernelcache"],
            @"sptm.static_artifact": @[@"sptm.img4", @"sptm.im4p"],
            @"txm.static_artifact": @[@"txm.img4", @"txm.im4p"],
        };
        [artifactNames enumerateKeysAndObjectsUsingBlock:^(NSString *checkpoint, NSArray<NSString *> *names, BOOL *stop) {
            NSString *location = artifactLocation(names);
            record(checkpoint, location ? @"AVAILABLE" : @"MISSING", location ?: @"not-packaged-or-in-Documents");
        }];

        NSString *targetVersion = @"26.0.1";
        NSString *targetBuild = @"23A355";
        NSArray<NSString *> *targetAliases = @[@"arm64e", @"iPhone14,2", @"A15"];
        BOOL (^containsTargetAlias)(NSArray *) = ^BOOL(NSArray *values) {
            for (NSString *value in values ?: @[]) {
                if ([targetAliases containsObject:value]) return YES;
            }
            return NO;
        };
        BOOL (^setAffectsTarget)(NSDictionary *) = ^BOOL(NSDictionary *set) {
            NSArray *devices = set[@"Devices"];
            return devices == nil || containsTargetAlias(devices);
        };

        NSString *frameworksPath = [bundlePath stringByAppendingPathComponent:@"Frameworks"];
        NSArray<NSString *> *frameworkNames = [[[NSFileManager defaultManager] contentsOfDirectoryAtPath:frameworksPath error:nil]
            sortedArrayUsingSelector:@selector(compare:)];
        NSString *(^packedVersionString)(uint32_t) = ^NSString *(uint32_t version) {
            return [NSString stringWithFormat:@"%u.%u.%u", version >> 16, (version >> 8) & 0xff, version & 0xff];
        };
        NSMutableArray<NSDictionary *> *binaryPreflight = [NSMutableArray new];
        for (NSString *frameworkName in @[@"ClearSword.framework", @"DarkSword.framework"]) {
            NSString *frameworkPath = [frameworksPath stringByAppendingPathComponent:frameworkName];
            NSDictionary *frameworkInfo = [NSDictionary dictionaryWithContentsOfFile:[frameworkPath stringByAppendingPathComponent:@"Info.plist"]];
            NSString *executableName = frameworkInfo[@"CFBundleExecutable"] ?: [frameworkName stringByDeletingPathExtension];
            NSString *executablePath = [frameworkPath stringByAppendingPathComponent:executableName];
            NSError *binaryError = nil;
            NSData *binaryData = [NSData dataWithContentsOfFile:executablePath options:NSDataReadingMappedIfSafe error:&binaryError];

            BOOL headerValid = NO;
            BOOL commandsValid = NO;
            NSString *minimumOS = @"unknown";
            NSString *sdkVersion = @"unknown";
            NSMutableArray<NSString *> *dependencies = [NSMutableArray new];
            if (binaryData.length >= sizeof(struct mach_header_64)) {
                struct mach_header_64 header = {0};
                [binaryData getBytes:&header length:sizeof(header)];
                NSUInteger commandStart = sizeof(header);
                NSUInteger commandEnd = commandStart + header.sizeofcmds;
                headerValid = header.magic == MH_MAGIC_64 && header.cputype == CPU_TYPE_ARM64 && commandEnd <= binaryData.length;
                commandsValid = headerValid;

                const uint8_t *bytes = binaryData.bytes;
                NSUInteger commandOffset = commandStart;
                for (uint32_t index = 0; commandsValid && index < header.ncmds; index++) {
                    if (commandOffset + sizeof(struct load_command) > commandEnd) {
                        commandsValid = NO;
                        break;
                    }

                    struct load_command loadCommand = {0};
                    memcpy(&loadCommand, bytes + commandOffset, sizeof(loadCommand));
                    if (loadCommand.cmdsize < sizeof(loadCommand) || commandOffset + loadCommand.cmdsize > commandEnd) {
                        commandsValid = NO;
                        break;
                    }

                    if (loadCommand.cmd == LC_BUILD_VERSION && loadCommand.cmdsize >= sizeof(struct build_version_command)) {
                        struct build_version_command buildVersion = {0};
                        memcpy(&buildVersion, bytes + commandOffset, sizeof(buildVersion));
                        minimumOS = packedVersionString(buildVersion.minos);
                        sdkVersion = packedVersionString(buildVersion.sdk);
                    }
                    else if ((loadCommand.cmd == LC_LOAD_DYLIB || loadCommand.cmd == LC_LOAD_WEAK_DYLIB || loadCommand.cmd == LC_REEXPORT_DYLIB) &&
                             loadCommand.cmdsize >= sizeof(struct dylib_command)) {
                        struct dylib_command dylibCommand = {0};
                        memcpy(&dylibCommand, bytes + commandOffset, sizeof(dylibCommand));
                        NSUInteger nameStart = commandOffset + dylibCommand.dylib.name.offset;
                        NSUInteger nameEnd = commandOffset + loadCommand.cmdsize;
                        if (nameStart < nameEnd) {
                            NSUInteger terminator = nameStart;
                            while (terminator < nameEnd && bytes[terminator] != 0) terminator++;
                            NSString *dependency = [[NSString alloc] initWithBytes:bytes + nameStart
                                                                           length:terminator - nameStart
                                                                         encoding:NSUTF8StringEncoding];
                            if (dependency.length > 0) [dependencies addObject:dependency];
                        }
                    }
                    commandOffset += loadCommand.cmdsize;
                }
                if (commandsValid && commandOffset != commandEnd) commandsValid = NO;
            }

            NSArray<NSString *> *markerNames = @[@"IOSurfacePrefetchPages", @"mach_make_memory_entry_64", @"PurpleGfxMem"];
            NSMutableDictionary<NSString *, NSNumber *> *markers = [NSMutableDictionary new];
            for (NSString *markerName in markerNames) {
                NSData *markerData = [markerName dataUsingEncoding:NSUTF8StringEncoding];
                BOOL present = binaryData != nil && [binaryData rangeOfData:markerData
                                                                    options:0
                                                                      range:NSMakeRange(0, binaryData.length)].location != NSNotFound;
                markers[markerName] = @(present);
            }

            NSDictionary *entry = @{
                @"framework": [frameworkName stringByDeletingPathExtension],
                @"present": @(binaryData != nil),
                @"size": @(binaryData.length),
                @"mach_o_arm64": @(headerValid),
                @"load_commands_valid": @(commandsValid),
                @"minimum_os": minimumOS,
                @"sdk": sdkVersion,
                @"dependencies": dependencies,
                @"static_markers": markers,
                @"error": binaryError.localizedDescription ?: @"none",
            };
            [binaryPreflight addObject:entry];
            record([NSString stringWithFormat:@"framework.%@.binary", [frameworkName stringByDeletingPathExtension].lowercaseString],
                   headerValid && commandsValid ? @"INSPECTED" : @"INVALID",
                   [NSString stringWithFormat:@"bytes=%lu minos=%@ dependencies=%lu loaded=false",
                    (unsigned long)binaryData.length, minimumOS, (unsigned long)dependencies.count]);
        }

        uint32_t hardwarePageSize = 0;
        size_t hardwarePageSizeLength = sizeof(hardwarePageSize);
        int pageSizeStatus = sysctlbyname("hw.pagesize", &hardwarePageSize, &hardwarePageSizeLength, NULL, 0);
        cpu_type_t hardwareCPUType = 0;
        size_t hardwareCPUTypeLength = sizeof(hardwareCPUType);
        int cpuTypeStatus = sysctlbyname("hw.cputype", &hardwareCPUType, &hardwareCPUTypeLength, NULL, 0);
        cpu_subtype_t hardwareCPUSubtype = 0;
        size_t hardwareCPUSubtypeLength = sizeof(hardwareCPUSubtype);
        int cpuSubtypeStatus = sysctlbyname("hw.cpusubtype", &hardwareCPUSubtype, &hardwareCPUSubtypeLength, NULL, 0);

        vm_address_t appOwnedAddress = 0;
        vm_size_t appOwnedSize = vm_page_size;
        kern_return_t allocationStatus = vm_allocate(mach_task_self(), &appOwnedAddress, appOwnedSize, VM_FLAGS_ANYWHERE);
        kern_return_t deallocationStatus = allocationStatus == KERN_SUCCESS
            ? vm_deallocate(mach_task_self(), appOwnedAddress, appOwnedSize)
            : KERN_FAILURE;
        BOOL appOwnedVMComplete = allocationStatus == KERN_SUCCESS && deallocationStatus == KERN_SUCCESS;
        NSDictionary *runtimePreflight = @{
            @"scope": @"mach_task_self/app-owned-page-only",
            @"vm_page_size": @(vm_page_size),
            @"hw_pagesize": @(hardwarePageSize),
            @"hw_pagesize_status": @(pageSizeStatus),
            @"hw_cputype": @(hardwareCPUType),
            @"hw_cputype_status": @(cpuTypeStatus),
            @"hw_cpusubtype": @(hardwareCPUSubtype),
            @"hw_cpusubtype_status": @(cpuSubtypeStatus),
            @"allocation_status": @(allocationStatus),
            @"deallocation_status": @(deallocationStatus),
            @"memory_written": @NO,
        };
        record(@"runtime.app_owned_vm", appOwnedVMComplete ? @"PASS" : @"FAIL",
               [NSString stringWithFormat:@"bytes=%lu allocate=%d deallocate=%d memory-written=false",
                (unsigned long)appOwnedSize, allocationStatus, deallocationStatus]);

        NSMutableArray<NSDictionary *> *exploitMatrix = [NSMutableArray new];
        NSMutableDictionary<NSString *, NSNumber *> *candidateCounts = [@{@"Kernel": @0, @"PAC": @0, @"PPL": @0} mutableCopy];
        NSMutableDictionary<NSString *, NSNumber *> *availableCounts = [@{@"Kernel": @0, @"PAC": @0, @"PPL": @0} mutableCopy];

        for (NSString *frameworkName in frameworkNames ?: @[]) {
            NSString *frameworkPath = [frameworksPath stringByAppendingPathComponent:frameworkName];
            NSDictionary *frameworkInfo = [NSDictionary dictionaryWithContentsOfFile:[frameworkPath stringByAppendingPathComponent:@"Info.plist"]];
            NSString *type = frameworkInfo[@"DPExploitType"];
            NSDictionary *flavors = frameworkInfo[@"DPExploitFlavors"];
            if (!type || !flavors) continue;

            NSString *displayName = frameworkInfo[@"CFBundleDisplayName"] ?: [frameworkName stringByDeletingPathExtension];
            for (NSString *flavorName in [[flavors allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
                NSDictionary *flavor = flavors[flavorName];
                NSArray *ranges = flavor[@"DPSupportedRanges"] ?: @[];
                NSArray *supportedDevices = flavor[@"DPSupportedDevices"];
                BOOL rangeMatch = NO;
                for (NSDictionary *range in ranges) {
                    NSString *start = range[@"Start"];
                    NSString *end = range[@"End"];
                    if (!start || !end) continue;
                    BOOL afterStart = [targetVersion compare:start options:NSNumericSearch] != NSOrderedAscending;
                    BOOL beforeEnd = [targetVersion compare:end options:NSNumericSearch] != NSOrderedDescending;
                    if (afterStart && beforeEnd) {
                        rangeMatch = YES;
                        break;
                    }
                }

                BOOL deviceMatch = supportedDevices == nil || containsTargetAlias(supportedDevices);
                BOOL supported = rangeMatch && deviceMatch;
                NSString *ruleKind = supported ? @"exclude" : @"include";
                NSArray *rules = supported ? flavor[@"DPSupportExclude"] : flavor[@"DPSupportInclude"];
                BOOL ruleConsidered = NO;
                BOOL ruleApplied = NO;
                for (NSDictionary *rule in rules ?: @[]) {
                    if (!setAffectsTarget(rule)) continue;
                    ruleConsidered = YES;
                    NSArray *builds = rule[@"Builds"];
                    if (builds == nil || [builds containsObject:targetBuild]) {
                        supported = !supported;
                        ruleApplied = YES;
                    }
                    break;
                }

                NSMutableArray<NSString *> *reasons = [NSMutableArray new];
                if (!rangeMatch) [reasons addObject:@"version-outside-declared-ranges"];
                if (!deviceMatch) [reasons addObject:@"device-family-not-declared"];
                if (ruleConsidered && !ruleApplied) [reasons addObject:@"metadata-override-build-miss"];
                if (ruleApplied && !supported) [reasons addObject:@"excluded-by-metadata-rule"];
                if (supported) [reasons addObject:@"eligible-by-packaged-metadata"];

                candidateCounts[type] = @(candidateCounts[type].unsignedIntegerValue + 1);
                if (supported) availableCounts[type] = @(availableCounts[type].unsignedIntegerValue + 1);
                [exploitMatrix addObject:@{
                    @"framework": displayName,
                    @"flavor": flavorName,
                    @"type": type,
                    @"priority": flavor[@"DPFlavorPriority"] ?: @0,
                    @"range_match": @(rangeMatch),
                    @"device_match": @(deviceMatch),
                    @"override_kind": ruleKind,
                    @"override_considered": @(ruleConsidered),
                    @"override_applied": @(ruleApplied),
                    @"supported": @(supported),
                    @"declared_ranges": ranges,
                    @"declared_devices": supportedDevices ?: @[],
                    @"reasons": reasons,
                }];
            }
        }

        record(@"selector.kernel", availableCounts[@"Kernel"].unsignedIntegerValue ? @"METADATA_ELIGIBLE" : @"METADATA_MISSING",
               [NSString stringWithFormat:@"eligible=%@ candidates=%@", availableCounts[@"Kernel"], candidateCounts[@"Kernel"]]);
        record(@"selector.pac", pacRequired ? (availableCounts[@"PAC"].unsignedIntegerValue ? @"METADATA_ELIGIBLE" : @"METADATA_MISSING") : @"NOT_REQUIRED",
               [NSString stringWithFormat:@"eligible=%@ candidates=%@", availableCounts[@"PAC"], candidateCounts[@"PAC"]]);
        record(@"selector.ppl", pplRequired ? (availableCounts[@"PPL"].unsignedIntegerValue ? @"METADATA_ELIGIBLE" : @"METADATA_MISSING") : @"NOT_REQUIRED",
               [NSString stringWithFormat:@"eligible=%@ candidates=%@", availableCounts[@"PPL"], candidateCounts[@"PPL"]]);
        NSString *selectorBlocker = availableCounts[@"Kernel"].unsignedIntegerValue == 0 ? @"kernel-exploit-missing" :
            (pplRequired && availableCounts[@"PPL"].unsignedIntegerValue == 0 ? @"ppl-bypass-missing" : @"none");
        record(@"selector.overall", [selectorBlocker isEqualToString:@"none"] ? @"METADATA_CHAIN_COMPLETE" : @"BLOCKED", selectorBlocker);

        record(@"kernel.runtime_read_write", @"MISSING", @"metadata-candidate-only-no-verified-runtime-primitive");
        record(@"titan.command_buffers", @"BLOCKED", @"diagnostic-mode");
        record(@"titan.physical_write", @"NOT_REACHED", @"physwritebuf-not-published");
        record(@"sptm_txm.runtime_response", @"NOT_REACHED", @"no-protected-component-request-issued");

        NSDictionary *report = @{
            @"schema": @"dopamine.a15-ios26.device-diagnostic.v3",
            @"diagnostic_only": @YES,
            @"asserts_live_sptm_txm_response": @NO,
            @"target": @{
                @"device": @"iPhone14,2",
                @"soc": @"A15",
                @"ios": @"26.0.1",
                @"build": @"23A355",
            },
            @"txm_static_base": @"0xfffffff017004000",
            @"binary_preflight": binaryPreflight,
            @"runtime_preflight": runtimePreflight,
            @"exploit_matrix": exploitMatrix,
            @"selector_counts": @{
                @"candidates": candidateCounts,
                @"eligible": availableCounts,
            },
            @"events": events,
        };

        NSError *jsonError = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&jsonError];
        NSString *outputPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/a15-ios26-diagnostic-v3.json"];
        BOOL wroteReport = json != nil && [json writeToFile:outputPath options:NSDataWritingAtomic error:&jsonError];
        [self emitResearchDiagnosticEvent:wroteReport
            ? @"checkpoint=report.write status=PASS path=Documents/a15-ios26-diagnostic-v3.json"
            : [NSString stringWithFormat:@"checkpoint=report.write status=FAIL error=%@", jsonError.localizedDescription ?: @"unknown"]];

        dispatch_async(dispatch_get_main_queue(), ^{
            [[DOUIManager sharedInstance] completeJailbreak];
        });
    });
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self.jailbreakBtn.button setTitle:[self jailbreakButtonTitle] forState:UIControlStateNormal];
}

- (void)startJailbreak
{
    DOJailbreaker *jailbreaker = [[DOJailbreaker alloc] init];

    [[DOUIManager sharedInstance] startLogCapture];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        if ([jailbreaker contiguousMappingWorkaroundNeeded]) {
            
            cpu_subtype_t cpuFamily = 0;
            size_t cpuFamilySize = sizeof(cpuFamily);
            sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
            NSString *workaroundMessage = DOLocalizedString(@"Respring_Required_Message");
            if (cpuFamily == CPUFAMILY_ARM_TYPHOON) {
                workaroundMessage = [workaroundMessage stringByAppendingString:[NSString stringWithFormat:@"\n\n%@", DOLocalizedString(@"Respring_Required_Notice_A8")]];
            }

            UIAlertController *contiguousMappingWorkaroundAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Respring_Required") message:workaroundMessage preferredStyle:UIAlertControllerStyleAlert];
            
            UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Respring_Cancel") style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
                exit(0);
            }];
            
            UIAlertAction *workaroundAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Apply_Workaround") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                [jailbreaker applyContiguousMappingWorkaround];
            }];
            
            [contiguousMappingWorkaroundAlertController addAction:cancelAction];
            [contiguousMappingWorkaroundAlertController addAction:workaroundAction];
            contiguousMappingWorkaroundAlertController.preferredAction = workaroundAction;

            dispatch_async(dispatch_get_main_queue(), ^{
                [self presentViewController:contiguousMappingWorkaroundAlertController animated:YES completion:nil];
            });
            return;
        }

        //We need to get the preconfig mutex to start the jailbreak (self.jailbreakBtn.canStartJailbreak)
        [self.jailbreakBtn lockMutex];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.hideHomeIndicator = YES;
        });

        NSError *error;
        BOOL didRemove = NO;
        BOOL showLogs = YES;
        [jailbreaker runWithError:&error didRemoveJailbreak:&didRemove showLogs:&showLogs];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error && showLogs) {
                [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Jailbreak failed with error: %@", error] debug:NO];
                [self.navigationController pushViewController:[[DOLogCrashViewController alloc] initWithTitle:[error localizedDescription]] animated:YES];
            }
            else if (error && !showLogs) {
                // Used when there is an error that is explainable in such detail that additional logs are not needed
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Log_Error") message:[error localizedDescription] preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Reboot") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    exec_cmd_trusted(JBROOT_PATH("/sbin/reboot"), NULL);
                }];
                [alertController addAction:rebootAction];
                [self presentViewController:alertController animated:YES completion:nil];
            }
            else if (didRemove) {
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Removed_Jailbreak_Alert_Title") message:DOLocalizedString(@"Removed_Jailbreak_Alert_Message") preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Close") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    exit(0);
                }];
                [alertController addAction:rebootAction];
                [self presentViewController:alertController animated:YES completion:nil];
            }
            else {
                // No errors
                [[DOUIManager sharedInstance] completeJailbreak];
                [self fadeToBlack: ^{
                    [jailbreaker finalize];
                }];
            }
        });
        [self.jailbreakBtn unlockMutex];
    });
}

-(void)setupUpdateAvailable:(BOOL)environmentUpdate
{
    if (self.jailbreakBtn.didExpand)
        return;

    NSString *title = environmentUpdate ? DOLocalizedString(@"Button_Update_Environment") : DOLocalizedString(@"Button_Update_Available");
    
    NSString *releaseFrom = [[DOUIManager sharedInstance] getLaunchedReleaseTag];
    NSString *releaseTo = [[DOUIManager sharedInstance] getLatestReleaseTag];

    if (environmentUpdate)
    {
        releaseFrom = [[DOEnvironmentManager sharedManager] jailbrokenVersion];
        releaseTo = [[DOUIManager sharedInstance] getLaunchedReleaseTag];
    }

    self.updateButton = [DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:title image:[UIImage systemImageNamed:@"arrow.down.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"update-available" handler:^(__kindof UIAction * _Nonnull action) {
        [self.navigationController pushViewController:[[DOUpdateViewController alloc] initFromTag:releaseFrom toTag:releaseTo] animated:YES];
    }] chevron:NO];

    self.updateButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.updateButton];

    [NSLayoutConstraint activateConstraints:@[
        [self.updateButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.updateButton.heightAnchor constraintEqualToConstant:30],
        [self.updateButton.bottomAnchor constraintEqualToAnchor:self.jailbreakBtn.topAnchor constant:[DOGlobalAppearance isHomeButtonDevice] ? -10 : -20]
    ]];

    [self.updateButton setTransform:CGAffineTransformMakeTranslation(0, 25)];
    [self.updateButton setAlpha:0];
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0  options: UIViewAnimationOptionCurveEaseInOut animations:^{
        [self.updateButton setTransform:CGAffineTransformIdentity];
        [self.updateButton setAlpha:1];
    } completion:nil];
}

-(void)simulateJailbreak
{
    // Let's simulate a "jailbreak" using grand central dispatch

    DOUIManager *uiManager = [DOUIManager sharedInstance];

    static BOOL didFinish = NO; //not thread safe lol
    

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [uiManager completeJailbreak];
        [uiManager sendLog:@"Rebooting Userspace" debug: NO];
        didFinish = YES;
        [self fadeToBlack: ^{

        }];
    });

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [NSThread sleepForTimeInterval:0.2];
        [uiManager sendLog:@"Launching kexploitd" debug: NO];
        [NSThread sleepForTimeInterval:0.5];
        [uiManager sendLog:@"Launching oobPCI" debug: NO];
        [NSThread sleepForTimeInterval:0.15];
        [uiManager sendLog:@"Gaining r/w" debug: NO];
        [NSThread sleepForTimeInterval:0.8];
        [uiManager sendLog:@"Patchfinding" debug: NO];
        NSArray *types = @[@"AMFI", @"PAC", @"KTRR", @"KPP", @"PPL", @"KPF", @"APRR", @"AMCC", @"PAN", @"PXN", @"ASLR", @"OPA"]; //Ever heard of the legendary opa bypass
        while (true)
        {
            [NSThread sleepForTimeInterval:0.6 * rand() / RAND_MAX];
            if (didFinish) break;
            NSString *type = types[arc4random_uniform((uint32_t)types.count)];
            [uiManager sendLog:[NSString stringWithFormat:@"Bypassing %@", type] debug: NO];
        }
    });
}

- (void)fadeToBlack:(void (^)(void))completion
{
    static bool didFade = false;
    if (didFade)
        return;
    didFade = true;
    UIView *mainView = self.parentViewController.view;
    float deviceCornerRadius = [[[UIScreen mainScreen] valueForKey:@"_displayCornerRadius"] floatValue];

    mainView.layer.cornerRadius = deviceCornerRadius;
    mainView.layer.cornerCurve = kCACornerCurveContinuous;
    mainView.layer.masksToBounds = YES;
    
    self.hideStatusBar = YES;

    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0 options: UIViewAnimationOptionCurveEaseInOut animations:^{
        mainView.transform = CGAffineTransformMakeScale(0.9, 0.9);
        mainView.alpha = 0.0;
    } completion:^(BOOL success) {
        completion();
    }];
}

#pragma mark - Action Menu Delegate

- (BOOL)actionMenuShowsChevronForAction:(UIAction *)action
{
    if ([action.identifier isEqualToString:@"settings"] || [action.identifier isEqualToString:@"credits"]) return YES;
    return NO;
}

- (BOOL)actionMenuActionIsEnabled:(UIAction *)action
{
    if ([action.identifier isEqualToString:@"respring"] || [action.identifier isEqualToString:@"reboot-userspace"]) {
        return [[DOEnvironmentManager sharedManager] isJailbroken];
    }
    return YES;
}

#pragma mark - Status Bar

- (UIStatusBarStyle)preferredStatusBarStyle
{
    return UIStatusBarStyleLightContent;
}

- (BOOL)prefersStatusBarHidden
{
    return self.hideStatusBar;
}

- (BOOL)prefersHomeIndicatorAutoHidden
{
    return self.hideHomeIndicator;
}

- (void)setHideStatusBar:(BOOL)hideStatusBar
{
    _hideStatusBar = hideStatusBar;
    [self setNeedsStatusBarAppearanceUpdate];
}

- (void)setHideHomeIndicator:(BOOL)hideHomeIndicator
{
    _hideHomeIndicator = hideHomeIndicator;
    [self setNeedsUpdateOfHomeIndicatorAutoHidden];
}

@end
