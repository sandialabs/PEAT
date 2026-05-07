#!/bin/bash
# Manual changelog generation script for PEAT
# Usage: ./scripts/build_changelog.sh <version>
# Example: ./scripts/build_changelog.sh 2.0.0

set -e

if [ -z "$1" ]; then
    echo "Error: Version argument required"
    echo "Usage: $0 <version>"
    echo "Example: $0 2.0.0"
    exit 1
fi

VERSION=$1

# Check if we're on main branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "Error: Must be on main branch to build changelog"
    echo "Current branch: $CURRENT_BRANCH"
    exit 1
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo "Error: Uncommitted changes detected. Please commit or stash changes first."
    exit 1
fi

# Build the changelog
echo "Building changelog for version $VERSION..."
towncrier build --version "$VERSION" --yes

# Show what changed
echo ""
echo "Changelog updates:"
git diff CHANGELOG.rst

echo ""
echo "Changelog successfully built!"
echo "Review the changes above, then commit with:"
echo "  git add CHANGELOG.rst"
echo "  git commit -m \"docs: update changelog for v$VERSION\""
