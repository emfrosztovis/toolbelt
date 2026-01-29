# toolbelt
A collection of little tools

## cleanmrc

This simple script removes colored background layers from PDF files scanned and compressed using the mixed raster content (MRC) method. Such files are common in most book-sharing sites e.g. Google Books, archive.org and Annas Archive. Typically, you would want to use this script on book scans with no colored graphics. It finds all images in the PDF file and performs the following: (1) for any masked image, replace the content by pure black while keeping the mask, where text shapes are stored; (2) assume all other images to be the background and delete them.

## fakemail

A mostly vibe coded GUI script to create emails with fake sender and timestamps in your inbox. Usage: first send to yourself what you want to fake. Then open the script. It will search for self-sent emails in your inbox, you can edit the sender and timestamp for each one you select. Click "Process" to generate the fake emails.

> Note: you have to delete the original self-sent mails manually after processing. Currently, only Gmail is supported, and you must supply an [App Password](https://support.google.com/mail/answer/185833) alongside your account name in the code.

## cropedges

Vibe coded script to remove black or white edges around an image. Usage:

```
uv run cropedges.py [-h] [-n MAX_PIXELS] [-t TOLERANCE] [--overwrite] files [files ...]
```
