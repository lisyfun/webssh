//go:build darwin && !server

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework WebKit
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

static WKWebView *websshFindWebView(NSView *v) {
	if ([v isKindOfClass:[WKWebView class]]) return (WKWebView *)v;
	for (NSView *sub in [v subviews]) {
		WKWebView *found = websshFindWebView(sub);
		if (found) return found;
	}
	return nil;
}

// websshApplyAppearance toggles a behind-window blur behind a transparent
// webview (frosted glass). When disabled it falls back to a plain window with
// the given whole-window alpha.
static void websshApplyAppearance(int vibrancy, double alpha) {
	dispatch_async(dispatch_get_main_queue(), ^{
		for (NSWindow *w in [NSApp windows]) {
			WKWebView *web = websshFindWebView([w contentView]);
			if (web == nil) continue;
			NSVisualEffectView *fx = nil;
			for (NSView *sub in [[w contentView] subviews]) {
				if ([sub isKindOfClass:[NSVisualEffectView class]]) { fx = (NSVisualEffectView *)sub; break; }
			}
			if (vibrancy) {
				@try {
					[web setValue:@NO forKey:@"drawsBackground"];
				} @catch (NSException *e) {}
				[w setOpaque:NO];
				[w setBackgroundColor:[NSColor clearColor]];
				if (fx == nil) {
					NSVisualEffectView *v = [[NSVisualEffectView alloc] initWithFrame:[[w contentView] bounds]];
					[v setMaterial:NSVisualEffectMaterialHUDWindow];
					[v setBlendingMode:NSVisualEffectBlendingModeBehindWindow];
					[v setState:NSVisualEffectStateActive];
					[v setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];
					[[w contentView] addSubview:v positioned:NSWindowBelow relativeTo:web];
					fx = v;
				}
				[fx setAlphaValue:alpha];
				[w setAlphaValue:1.0];
			} else {
				if (fx) [fx removeFromSuperview];
				@try {
					[web setValue:@YES forKey:@"drawsBackground"];
				} @catch (NSException *e) {}
				[w setOpaque:YES];
				[w setBackgroundColor:[NSColor windowBackgroundColor]];
				[w setAlphaValue:alpha];
			}
		}
	});
}
*/
import "C"

// applyWindowAppearance enables/disables the frosted-glass backdrop and sets
// its strength (vibrancy) or the whole-window alpha (plain mode).
func applyWindowAppearance(vibrancy bool, opacity float64) {
	v := C.int(0)
	if vibrancy {
		v = 1
	}
	C.websshApplyAppearance(v, C.double(opacity))
}
