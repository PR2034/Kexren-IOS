//
// ViewController.mm — ACLuna-External full flow.
//
// Phase 1: Run DarkSword kernel exploit → get kernel R/W
// Phase 2: Attach to CODM (fabricate task port via kernel R/W)
// Phase 3: Launch overlay window + ESP rendering
//

#import "ViewController.h"
#import "../kexploit/darksword.h"
#import "../kexploit/offsets.h"
#import "../kexploit/utils.h"
#import "ExternalRead.h"
#import "ExtGameAPI.h"

// ============================================================================
//  ESP Overlay Window — transparent, non-interactive, renders on top of CODM.
//
//  We create a UIWindow at UIWindowLevelAlert so it floats above everything.
//  A CADisplayLink drives per-frame ESP drawing via CoreGraphics.
// ============================================================================
@interface ESPOverlayView : UIView
@end

@implementation ESPOverlayView

- (instancetype)initWithFrame:(CGRect)frame {
    if ((self = [super initWithFrame:frame])) {
        self.backgroundColor = [UIColor clearColor];
        self.userInteractionEnabled = NO;
        self.opaque = NO;
    }
    return self;
}

- (void)drawRect:(CGRect)rect {
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    if (!ctx || !ext_is_attached()) return;

    int count = extgame_update();
    uint32_t localTeam = extgame_get_local_team();

    for (int i = 0; i < count; i++) {
        const ExtEnemyData *e = extgame_get_enemy(i);
        if (!e || !e->valid || !e->isAlive) continue;
        if (e->teamId == localTeam) continue;

        float sx, sy;
        if (!extgame_w2s(e->position, &sx, &sy)) continue;

        // ESP box.
        float dist = sqrtf(
            powf(e->position.x - extgame_get_local_pos().x, 2) +
            powf(e->position.y - extgame_get_local_pos().y, 2) +
            powf(e->position.z - extgame_get_local_pos().z, 2));

        float boxH = fmaxf(20.0f, 800.0f / fmaxf(dist, 1.0f));
        float boxW = boxH * 0.5f;

        CGContextSetStrokeColorWithColor(ctx, [UIColor whiteColor].CGColor);
        CGContextSetLineWidth(ctx, 1.5f);
        CGContextStrokeRect(ctx, CGRectMake(sx - boxW/2, sy - boxH, boxW, boxH));

        // Health bar.
        float hp = (e->maxHealth > 0) ? (e->health / e->maxHealth) : 0;
        hp = fminf(1.0f, fmaxf(0.0f, hp));
        float barH = boxH * hp;
        CGContextSetFillColorWithColor(ctx,
            [UIColor colorWithRed:1-hp green:hp blue:0 alpha:0.8].CGColor);
        CGContextFillRect(ctx, CGRectMake(sx - boxW/2 - 5, sy - boxH + (boxH - barH), 3, barH));

        // Name.
        if (e->nameLen > 0) {
            NSString *name = [NSString stringWithCharacters:e->nameUTF16 length:e->nameLen];
            NSDictionary *attrs = @{
                NSFontAttributeName: [UIFont boldSystemFontOfSize:10],
                NSForegroundColorAttributeName: [UIColor whiteColor]
            };
            [name drawAtPoint:CGPointMake(sx - boxW/2, sy - boxH - 14) withAttributes:attrs];
        }

        // Distance.
        NSString *distStr = [NSString stringWithFormat:@"%.0fm", dist];
        NSDictionary *dAttrs = @{
            NSFontAttributeName: [UIFont systemFontOfSize:9],
            NSForegroundColorAttributeName: [UIColor colorWithWhite:0.85 alpha:1.0]
        };
        [distStr drawAtPoint:CGPointMake(sx - boxW/2, sy + 2) withAttributes:dAttrs];

        // Skeleton.
        if (e->bonesValid) {
            static const int connections[][2] = {
                {0,1},{1,2},{2,6},   // left leg
                {3,4},{4,5},{5,6},   // right leg
                {6,15},              // hips → body
                {15,14},{14,10},     // body → neck → head
                {14,9},{9,8},{8,7},  // left arm
                {14,13},{13,12},{12,11} // right arm
            };

            CGContextSetStrokeColorWithColor(ctx, [UIColor colorWithRed:0.4 green:0.9 blue:1.0 alpha:0.9].CGColor);
            CGContextSetLineWidth(ctx, 2.0f);

            for (int c = 0; c < 15; c++) {
                int a = connections[c][0], b = connections[c][1];
                float ax, ay, bx, by;
                if (!extgame_w2s(e->bones[a], &ax, &ay)) continue;
                if (!extgame_w2s(e->bones[b], &bx, &by)) continue;

                CGContextMoveToPoint(ctx, ax, ay);
                CGContextAddLineToPoint(ctx, bx, by);
                CGContextStrokePath(ctx);
            }
        }
    }
}

@end

// ============================================================================
//  Main ViewController
// ============================================================================
@interface ViewController ()
@property (nonatomic, strong) UILabel*  statusLabel;
@property (nonatomic, strong) UILabel*  progressLabel;
@property (nonatomic, strong) UIButton* runButton;
@property (nonatomic, strong) UIButton* attachButton;
@property (nonatomic, strong) UIWindow* overlayWindow;
@property (nonatomic, strong) ESPOverlayView* espView;
@property (nonatomic, strong) CADisplayLink* displayLink;
@end

@implementation ViewController

static __weak ViewController* g_vc = nil;

static void s_log_cb(const char* msg)
{
    NSString* line = msg ? @(msg) : @"(null)";
    dispatch_async(dispatch_get_main_queue(), ^{
        ViewController* vc = g_vc;
        if (!vc) return;
        NSArray<NSString*>* lines = [vc.statusLabel.text componentsSeparatedByString:@"\n"];
        NSMutableArray<NSString*>* keep = [lines mutableCopy];
        [keep addObject:line];
        while (keep.count > 20) [keep removeObjectAtIndex:0];
        vc.statusLabel.text = [keep componentsJoinedByString:@"\n"];
    });
}

static void s_prog_cb(double p)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        ViewController* vc = g_vc;
        if (!vc) return;
        vc.progressLabel.text = [NSString stringWithFormat:@"Progress: %.0f%%", p * 100.0];
    });
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    g_vc = self;
    self.view.backgroundColor = [UIColor blackColor];

    UILabel* title = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, self.view.bounds.size.width - 40, 36)];
    title.text = @"ACLuna-External";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:22];
    [self.view addSubview:title];

    UILabel* sub = [[UILabel alloc] initWithFrame:CGRectMake(20, 96, self.view.bounds.size.width - 40, 20)];
    sub.text = @"Kernel R/W + External CODM overlay";
    sub.textColor = [UIColor colorWithWhite:0.7 alpha:1.0];
    sub.font = [UIFont systemFontOfSize:13];
    [self.view addSubview:sub];

    // Run Exploit button.
    _runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _runButton.frame = CGRectMake(20, 130, self.view.bounds.size.width - 40, 50);
    _runButton.backgroundColor = [UIColor colorWithRed:0.25 green:0.52 blue:0.66 alpha:1.0];
    [_runButton setTitle:@"1. Run Exploit" forState:UIControlStateNormal];
    [_runButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    _runButton.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    _runButton.layer.cornerRadius = 10;
    [_runButton addTarget:self action:@selector(runTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_runButton];

    // Attach to CODM button.
    _attachButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _attachButton.frame = CGRectMake(20, 195, self.view.bounds.size.width - 40, 50);
    _attachButton.backgroundColor = [UIColor colorWithRed:0.15 green:0.15 blue:0.15 alpha:1.0];
    [_attachButton setTitle:@"2. Attach to CODM" forState:UIControlStateNormal];
    [_attachButton setTitleColor:[UIColor colorWithWhite:0.4 alpha:1.0] forState:UIControlStateNormal];
    _attachButton.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    _attachButton.layer.cornerRadius = 10;
    _attachButton.enabled = NO;
    [_attachButton addTarget:self action:@selector(attachTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_attachButton];

    // Progress.
    _progressLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 260, self.view.bounds.size.width - 40, 20)];
    _progressLabel.text = @"Step 1: Tap to run exploit.";
    _progressLabel.textColor = [UIColor colorWithWhite:0.85 alpha:1.0];
    _progressLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightMedium];
    [self.view addSubview:_progressLabel];

    // Status log.
    _statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 290,
                                                              self.view.bounds.size.width - 40,
                                                              self.view.bounds.size.height - 310)];
    _statusLabel.text = @"";
    _statusLabel.textColor = [UIColor greenColor];
    _statusLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    _statusLabel.numberOfLines = 0;
    _statusLabel.lineBreakMode = NSLineBreakByCharWrapping;
    [self.view addSubview:_statusLabel];

    ds_set_log_callback(&s_log_cb);
    ds_set_progress_callback(&s_prog_cb);
    ext_set_log_callback(&s_log_cb);

    offsets_init();
}

- (void)runTapped
{
    _runButton.enabled = NO;
    [_runButton setTitle:@"Running..." forState:UIControlStateNormal];
    _statusLabel.text = @"";
    _progressLabel.text = @"Progress: starting...";

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int rc = ds_run();
        bool ok = ds_is_ready();
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!ok) {
                self.progressLabel.text = [NSString stringWithFormat:@"Exploit failed (rc=%d).", rc];
                self.progressLabel.textColor = [UIColor redColor];
                self.runButton.enabled = YES;
                [self.runButton setTitle:@"1. Run Exploit" forState:UIControlStateNormal];
                return;
            }

            uint64_t kb = ds_get_kernel_base();
            uint64_t ks = ds_get_kernel_slide();
            uint64_t probe = ds_kread64(kb);
            NSString* msg = [NSString stringWithFormat:
                @"kernel R/W ready\n"
                @"kernel_base  = 0x%016llx\n"
                @"kernel_slide = 0x%016llx\n"
                @"kread64(kbase) = 0x%016llx",
                kb, ks, probe];
            s_log_cb(msg.UTF8String);

            self.progressLabel.text = @"Step 1 DONE. Now open CODM, then tap Step 2.";
            self.progressLabel.textColor = [UIColor greenColor];
            [self.runButton setTitle:@"Exploit OK" forState:UIControlStateNormal];
            self.runButton.backgroundColor = [UIColor colorWithRed:0.15 green:0.5 blue:0.15 alpha:1.0];

            // Enable step 2.
            self.attachButton.enabled = YES;
            self.attachButton.backgroundColor = [UIColor colorWithRed:0.6 green:0.25 blue:0.15 alpha:1.0];
            [self.attachButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        });
    });
}

- (void)attachTapped
{
    _attachButton.enabled = NO;
    [_attachButton setTitle:@"Attaching..." forState:UIControlStateNormal];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        // offsets_init() already ran in viewDidLoad — all struct offsets are set.
        // dlkcache() is skipped: it hangs in GBox sandbox (network download).
        // Our find_codm_proc() walks from proc_self(), no kernproc symbol needed.

        // Initialize utils offsets (PROC_PID_OFFSET, THREAD_MUPCB, etc.)
        init_offsets();

        s_log_cb("searching for CODM...");
        int rc = ext_attach();
        dispatch_async(dispatch_get_main_queue(), ^{
            if (rc != 0) {
                NSString *hint;
                switch (rc) {
                    case -2: hint = @"Is CODM open?"; break;
                    case -3: hint = @"Task resolution failed."; break;
                    case -4: hint = @"Pmap/physmap failed — check log."; break;
                    case -5: hint = @"Kernel exception — check log."; break;
                    default: hint = @"Unknown error."; break;
                }
                self.progressLabel.text = [NSString stringWithFormat:@"Attach failed (%d). %@", rc, hint];
                self.progressLabel.textColor = [UIColor redColor];
                self.attachButton.enabled = YES;
                [self.attachButton setTitle:@"2. Attach to CODM" forState:UIControlStateNormal];
                return;
            }

            s_log_cb([[NSString stringWithFormat:@"Attached to CODM pid=%d base=0x%llx",
                       ext_codm_pid(), ext_codm_base()] UTF8String]);

            self.progressLabel.text = @"Attached! Launching overlay...";
            self.progressLabel.textColor = [UIColor greenColor];
            self.attachButton.backgroundColor = [UIColor colorWithRed:0.15 green:0.5 blue:0.15 alpha:1.0];
            [self.attachButton setTitle:@"Attached" forState:UIControlStateNormal];

            extgame_init();
            [self launchOverlay];
        });
    });
}

- (void)launchOverlay
{
    // Create a transparent overlay window at alert level.
    UIWindowScene *scene = (UIWindowScene *)self.view.window.windowScene;
    if (!scene) {
        s_log_cb("no window scene — cannot create overlay");
        return;
    }

    _overlayWindow = [[UIWindow alloc] initWithWindowScene:scene];
    _overlayWindow.frame = [UIScreen mainScreen].bounds;
    _overlayWindow.windowLevel = UIWindowLevelAlert + 100;
    _overlayWindow.backgroundColor = [UIColor clearColor];
    _overlayWindow.opaque = NO;
    _overlayWindow.userInteractionEnabled = NO;
    _overlayWindow.hidden = NO;

    _espView = [[ESPOverlayView alloc] initWithFrame:_overlayWindow.bounds];
    [_overlayWindow addSubview:_espView];

    // Drive rendering at display refresh rate.
    _displayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(espTick)];
    _displayLink.preferredFramesPerSecond = 30;
    [_displayLink addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];

    s_log_cb("ESP overlay launched — switch to CODM now.");
    self.progressLabel.text = @"Overlay active. Switch to CODM!";
}

- (void)espTick
{
    [_espView setNeedsDisplay];
}

@end
