//go:build darwin && !server

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#include <Cocoa/Cocoa.h>

// websshShiftTrafficLights moves the window button container down by dy points.
// Wails has no public API for the traffic-light position; with a hidden title
// bar macOS keeps them at the standard ~16pt centre, which sits high in our
// 42pt custom top bar. The original frame is captured once so repeated calls
// (the window may not exist yet at startup) stay idempotent.
static void websshShiftTrafficLights(double dy) {
	dispatch_async(dispatch_get_main_queue(), ^{
		static NSView *tracked = nil;
		static CGFloat originalY = 0;
		for (NSWindow *w in [NSApp windows]) {
			NSButton *close = [w standardWindowButton:NSWindowCloseButton];
			NSView *container = [close superview];
			if (container == nil) continue;
			if (container != tracked) {
				tracked = container;
				originalY = [container frame].origin.y;
			}
			NSRect f = [container frame];
			f.origin.y = originalY - dy;
			[container setFrame:f];
		}
	});
}
*/
import "C"

import "time"

// adjustTrafficLightsAfterStartup nudges the macOS traffic lights so they are
// vertically centred in the 42pt custom top bar. Retried because the window may
// not exist when ServiceStartup runs; the ObjC side is idempotent.
func adjustTrafficLightsAfterStartup() {
	go func() {
		for i := 0; i < 4; i++ {
			time.Sleep(400 * time.Millisecond)
			C.websshShiftTrafficLights(C.double(5))
		}
	}()
}
