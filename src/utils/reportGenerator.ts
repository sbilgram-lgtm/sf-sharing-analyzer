import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { AssessmentResult, SharingFinding } from '../types/assessment';

export function generatePDFReport(assessment: AssessmentResult) {
  const doc = new jsPDF();
  const allFindings: SharingFinding[] = assessment.categories.flatMap(c => c.items);

  // Title page
  doc.setFontSize(22);
  doc.setTextColor(26, 86, 219);
  doc.text('SF Sharing Analyzer', 20, 30);
  doc.setFontSize(14);
  doc.setTextColor(100, 100, 100);
  doc.text('Sharing & Visibility Architecture Review', 20, 40);

  doc.setFontSize(11);
  doc.setTextColor(50, 50, 50);
  doc.text(`Org: ${assessment.orgName || 'Unknown'}`, 20, 55);
  doc.text(`Type: ${assessment.orgType || 'Unknown'}${assessment.isSandbox ? ' (Sandbox)' : ''}`, 20, 63);
  doc.text(`Overall Sharing Score: ${assessment.overallScore}%`, 20, 71);
  doc.text(`Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`, 20, 79);

  // Severity summary
  const counts = {
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
  };
  doc.text(`Findings: ${counts.critical} Critical · ${counts.high} High · ${counts.medium} Medium · ${counts.low} Low`, 20, 89);

  // Category scores table
  doc.addPage();
  doc.setFontSize(14);
  doc.setTextColor(26, 86, 219);
  doc.text('Category Scores', 20, 20);

  autoTable(doc, {
    startY: 28,
    head: [['Category', 'Score', 'Findings']],
    body: assessment.categories.map(c => [
      c.category,
      `${c.score}%`,
      c.items.length > 0 ? c.items.length.toString() : 'None'
    ]),
    styles: { fontSize: 9 },
    headStyles: { fillColor: [26, 86, 219] }
  });

  // Findings detail
  doc.addPage();
  doc.setFontSize(14);
  doc.setTextColor(26, 86, 219);
  doc.text('Findings Detail', 20, 20);

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const sorted = [...allFindings].sort((a, b) =>
    severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  autoTable(doc, {
    startY: 28,
    head: [['Severity', 'Category', 'Finding', 'Recommendation']],
    body: sorted.map(f => [
      f.severity.toUpperCase(),
      f.category,
      f.title,
      f.remediation.slice(0, 120)
    ]),
    styles: { fontSize: 8, cellPadding: 3 },
    headStyles: { fillColor: [26, 86, 219] },
    columnStyles: {
      0: { cellWidth: 18, fontStyle: 'bold' },
      1: { cellWidth: 35 },
      2: { cellWidth: 70 },
      3: { cellWidth: 60 }
    },
    didParseCell: (data: any) => {
      if (data.column.index === 0 && data.section === 'body') {
        const sev = data.cell.text[0]?.toLowerCase();
        if (sev === 'critical') data.cell.styles.textColor = [192, 57, 43];
        else if (sev === 'high') data.cell.styles.textColor = [211, 84, 0];
        else if (sev === 'medium') data.cell.styles.textColor = [243, 156, 18];
        else data.cell.styles.textColor = [39, 174, 96];
      }
    }
  });

  doc.save(`SF_Sharing_Analyzer_${(assessment.orgName || 'Report').replace(/\s+/g, '_')}_${new Date().toISOString().slice(0, 10)}.pdf`);
}
