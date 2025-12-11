#!/bin/bash
# AegisAI Linux DEB Package Build Script

echo "Building AegisAI DEB Package..."

# Create package directory structure
mkdir -p ../../build/debian/aegisai/usr/bin
mkdir -p ../../build/debian/aegisai/usr/lib/aegisai
mkdir -p ../../build/debian/aegisai/usr/share/doc/aegisai
mkdir -p ../../build/debian/aegisai/usr/share/man/man1
mkdir -p ../../build/debian/aegisai/etc/aegisai
mkdir -p ../../build/debian/aegisai/var/lib/aegisai

# Copy files
cp -R ../../dist/* ../../build/debian/aegisai/usr/lib/aegisai/
cp ../../LICENSE ../../build/debian/aegisai/usr/share/doc/aegisai/copyright
cp ../../README.md ../../build/debian/aegisai/usr/share/doc/aegisai/README

# Create symlink for executable
ln -s /usr/lib/aegisai/aegisai.py ../../build/debian/aegisai/usr/bin/aegisai

# Create DEB control file
mkdir -p ../../build/debian/aegisai/DEBIAN
cat > ../../build/debian/aegisai/DEBIAN/control << EOF
Package: aegisai
Version: 1.0.0
Section: utils
Priority: optional
Architecture: all
Depends: python3, python3-watchdog, python3-yara
Maintainer: AegisAI Security <security@aegisai.com>
Description: AegisAI Antivirus - AI-powered antivirus solution
 Advanced antivirus and antimalware solution with real-time protection,
 AI-based detection, and comprehensive threat intelligence integration.
EOF

# Create postinst script
cat > ../../build/debian/aegisai/DEBIAN/postinst << EOF
#!/bin/bash
echo "AegisAI installation complete!"
echo "Run 'aegisai' to start the antivirus engine."
EOF

chmod 755 ../../build/debian/aegisai/DEBIAN/postinst

# Build DEB package
dpkg-deb --build ../../build/debian/aegisai ../../dist/aegisai_1.0.0_all.deb

echo "DEB package build complete!"
echo "Package location: ../../dist/aegisai_1.0.0_all.deb"