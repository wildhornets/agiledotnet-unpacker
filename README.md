# agiledotnet-unpacker

Static Agile.NET unpacker for inspecting recovered C# in dnSpy.

**Tested on SeroXen RAT** protected with Agile.NET 6.6 / C5VM 6.6.0.11.
The runtime version comes from C5VM's assembly and file metadata. This is a
tested sample profile, not support for every Agile.NET build.

## Before / after

The same button-paint method, decompiled in dnSpy. Before recovery, the protected
file exposes a one-byte `ret`, so the decompiler shows an empty body. After
recovery, the drawing code is visible. The snippets below are from the actual
sample; only whitespace has been adjusted.

**Before** — `ohM=.vhM=::OnPaint`

```csharp
protected override void OnPaint(PaintEventArgs e)
{
}
```

**After** — `Recovered.Group013.Button_0008::OnPaint`

```csharp
protected override void OnPaint(PaintEventArgs e)
{
    base.OnPaint(e);
    e.Graphics.FillRectangle(
        new LinearGradientBrush(
            PointF.Empty,
            new PointF((float)base.Width, (float)base.Height),
            Color.Purple, Color.DeepPink),
        new RectangleF(PointF.Empty, base.Size));

    SizeF sizeF = e.Graphics.MeasureString(this.Text, this.Font);
    PointF pointF = new PointF(
        (float)(base.Width / 2) - sizeF.Width / 2f,
        (float)(base.Height / 2) - sizeF.Height / 2f);
    e.Graphics.DrawString(this.Text, this.Font, Brushes.Black, pointF);

    RectangleF rectangleF = new RectangleF(0f, 0f, (float)base.Width, (float)base.Height);
    using (GraphicsPath graphicsPath = this.Method_0029(rectangleF, 50))
    {
        base.Region = new Region(graphicsPath);
        using (Pen pen = new Pen(Color.Black, 1.75f))
        {
            pen.Alignment = PenAlignment.Inset;
            e.Graphics.DrawPath(pen, graphicsPath);
        }
    }
}
```

The method grows from **1 to 381 bytes of IL**. Names such as `Button_0008` and
`Method_0029` are generated labels, not recovered original names.

On the tested sample:

| Result | Count |
| --- | ---: |
| Non-VM method bodies recovered | 1,564 |
| VM methods recovered | 136 / 136 |
| Remaining VM dispatcher stubs | 0 |
| Top-level C# files exported | 375 |

## Requirements

- Windows x64, Python 3.11 and the .NET 8 runtime.
- For optional cleanup: PowerShell 7 and a trusted copy of dnlib 3.5.0.
- dnSpy to inspect the result.

Python uses the standard library. The prebuilt static VM lifter is included in
`vendor/`. No C# compiler is needed.

## Usage

Keep the input and its matching `C5VM.dll` together. Replace the paths below
with your own. Every output directory must be new.

```powershell
python -B .\make_readable.py 'D:\analysis\sample.exe' `
    --runtime 'D:\analysis\C5VM.dll' `
    --out 'D:\analysis\unpacked'
```

The recovered assembly is `D:\analysis\unpacked\result\SeroXen.unpacked.bin`.
Open it in dnSpy. Check `report.json` for recovery status; a partial result is
not full recovery.

For the tested profile, optional cleanup removes the remaining C5VM helpers
and replaces obfuscated identifiers with readable labels:

```powershell
pwsh -NoProfile -File .\clean_readable.ps1 `
    -InputDirectory 'D:\analysis\unpacked\result' `
    -OutputDirectory 'D:\analysis\clean' `
    -DnlibPath 'D:\tools\dnlib.dll'
```

Open `D:\analysis\clean\result\SeroXen.cleaned.bin` in dnSpy. Cleanup checks
the input hashes and rejects unsupported profiles. Supported source and runtime
hashes are recorded in [`VERSION.json`](VERSION.json).

## Scope

This is an analysis tool. It does not run the inspected application or compile
the recovered code. Readable C# does not mean the output is safe to run, that it
will compile, or that all original names and runtime behavior are preserved.
Use it only for authorized analysis, and keep both inputs and results isolated.

Samples, C5VM runtimes and recovered applications are not distributed here.
Local `result/` files are excluded by `.gitignore`.

## Tests

```powershell
python -B -m unittest discover -s tests -v
```

These tests use the bundled utility and synthetic data, not a malware sample.

## Credits / license

VM lifting uses [agile-net-devirtualizer](https://github.com/dawwinci/agile-net-devirtualizer)
v1.0.1 with the static fixes in `patches/`. The method-recovery work also draws
on de4dot and AgileDotNetSlayer; see [`SOURCES.txt`](SOURCES.txt).

Project scripts: **GPL-3.0-or-later**. Bundled third-party components retain their
own licenses; see [`LICENSE`](LICENSE) and the notices in `vendor/`.
