//go:build darwin && !server

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework CoreText
#import <Cocoa/Cocoa.h>
#import <CoreText/CoreText.h>

static CFArrayRef websshFontFamilies(void) {
	return CTFontManagerCopyAvailableFontFamilyNames();
}

static void websshCFStringToBuf(CFStringRef s, char *buf, CFIndex len) {
	CFStringGetCString(s, buf, len, kCFStringEncodingUTF8);
}

static int websshFamilyIsMonospace(CFStringRef name) {
	CTFontRef f = CTFontCreateWithName(name, 12.0, NULL);
	if (f == NULL) return 0;
	CTFontSymbolicTraits traits = CTFontGetSymbolicTraits(f);
	CFRelease(f);
	return (traits & kCTFontTraitMonoSpace) ? 1 : 0;
}

static void websshRelease(CFTypeRef ref) {
	CFRelease(ref);
}
*/
import "C"

import (
	"sort"
	"strings"
	"unsafe"
)

// listLocalFonts enumerates installed font families, monospace first.
func listLocalFonts() []LocalFont {
	arr := C.websshFontFamilies()
	if unsafe.Pointer(arr) == nil {
		return nil
	}
	defer C.websshRelease(C.CFTypeRef(unsafe.Pointer(arr)))

	count := int(C.CFArrayGetCount(arr))
	buf := C.malloc(1024)
	defer C.free(buf)

	out := make([]LocalFont, 0, count)
	seen := make(map[string]bool, count)
	for i := 0; i < count; i++ {
		ref := C.CFArrayGetValueAtIndex(arr, C.CFIndex(i))
		if ref == nil {
			continue
		}
		s := C.CFStringRef(unsafe.Pointer(ref))
		C.websshCFStringToBuf(s, (*C.char)(buf), 1024)
		name := C.GoString((*C.char)(buf))
		if name == "" || strings.HasPrefix(name, ".") || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, LocalFont{
			Family:    name,
			Monospace: C.websshFamilyIsMonospace(s) != 0,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Monospace != out[j].Monospace {
			return out[i].Monospace
		}
		return out[i].Family < out[j].Family
	})
	return out
}
