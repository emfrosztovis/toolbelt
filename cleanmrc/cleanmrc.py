# cleanmrc.py
# version 1.1
# -- fix for files using /Mask, not /SMask

from pathlib import Path
import argparse

try:
    from pikepdf import Pdf, Name
except ImportError:
    print('One or more modules not found.')
    print('Make sure you have installed the pikepdf library:')
    print('pip install pikepdf')
    exit()

skipFirst = 0
skipLast = 0

emptyData = b'x\x9cc\x00\x00\x00\x01\x00\x01'

def processFile(filename):
    try:
        filepath = Path(filename)
        file = Pdf.open(filepath)
    except:
        print('Error: failed opening ' + filepath)
        return

    def createEmptyImage():
        new_image = file.make_stream(b'\xff')
        new_image.Width, new_image.Height = 1, 1
        new_image.BitsPerComponent = 1
        new_image.ImageMask = True
        new_image.Decode = [0, 1]
        return new_image

    def replaceImages(page):
        if '/Resources' not in page or '/XObject' not in page['/Resources']:
            return
        xobjs = page.Resources.XObject
        replace = []
        modify = []
        for name in xobjs:
            xobj = xobjs[name]
            if xobj.Subtype == '/Image':
                if '/SMask' not in xobj and '/Mask' not in xobj:
                    replace.append(name)
                else:
                    modify.append(name)
        for name in replace:
            xobjs[name] = createEmptyImage()
        for name in modify:
            obj = xobjs[name]
            obj.ColorSpace = Name("/DeviceGray")
            obj.BitsPerComponent = 1
            obj.write(emptyData, filter=Name("/FlateDecode"))

    pages = file.pages
    if len(pages) > skipFirst:
        pages = pages[skipFirst:]
    if skipLast > 0 and len(pages) > skipLast:
        pages = pages[:-skipLast]
    for page in pages:
        replaceImages(page)
    outpath = filepath.with_stem(filepath.stem + ' [clean]')
    file.save(outpath)
    print('Cleaned file saved at ' + str(outpath))

parser = argparse.ArgumentParser(
    description='Remove colored background layers from PDF files scanned and compressed using the mixed raster content (MRC) method. Such files are common in most book-sharing sites e.g. Google Books, archive.org and Annas Archive. Typically, you would want to use this script on book scans with no colored graphics.',
    epilog='This simple script finds all images in the PDF file and performs the following: (1) for any masked image, replace the content by pure black while keeping the mask, where text shapes are stored; (2) assume all other images to be the background and delete them.')

parser.add_argument('path', nargs='+')
parser.add_argument('-sf', '--skipfirst', metavar='N', type=int, default=0, help='do not process the first N pages (usually cover)')
parser.add_argument('-sl', '--skiplast', metavar='N', type=int, default=0, help='do not process the last N pages (usually back cover)')
args = parser.parse_args()
skipFirst = args.skipfirst
skipLast = args.skiplast
for filename in args.path:
    processFile(filename)
    
