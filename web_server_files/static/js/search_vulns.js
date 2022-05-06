
var curVulnData = {};
var ignoreGeneralCpeVulns = false;
var iconUnsorted = '<i class="fa-solid fa-sort"></i>';
var iconSortDesc = '<i class="fa-solid fa-sort-down"></i>';
var iconSortAsc = '<i class="fa-solid fa-sort-up"></i>';


function createVulnsHtml(sortColumnIdx, asc) {
    var sortIconCVEID = iconUnsorted, sortFunctionCVEID = "reorderVulns(0, false)";
    var sortIconCVSS = iconUnsorted, sortFunctionCVSS = "reorderVulns(1, false)";
    var sortIconExploits = iconUnsorted, sortFunctionExploits = "reorderVulns(3, false)";

    // retrieve and sort vulns
    vulns = Object.values(Object.values(curVulnData)[0]);
    console.log(curVulnData);
    if (sortColumnIdx == 0) {  // CVE-ID
        if (asc) {
            vulns = vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            });
            sortIconCVEID = iconSortAsc;
            sortFunctionCVEID = "reorderVulns(0, false)";
        }
        else {
            vulns = vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            });
            vulns = vulns.reverse();
            sortIconCVEID = iconSortDesc;
            sortFunctionCVEID = "reorderVulns(0, true)";
        }
    }
    else if (sortColumnIdx == 1) {  // CVSS
        if (asc) {
            vulns = vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln1.cvss) - parseFloat(vuln2.cvss);
            });
            sortIconCVSS = iconSortAsc;
            sortFunctionCVSS = "reorderVulns(1, false)";
        }
        else {
            vulns = vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln2.cvss) - parseFloat(vuln1.cvss);
            });
            sortIconCVSS = iconSortDesc;
            sortFunctionCVSS = "reorderVulns(1, true)";
        }
    }
    else if (sortColumnIdx == 3) {  // Exploits
        if (asc) {
            vulns = vulns.sort(function (vuln1, vuln2) {
                exploits1 = vuln1.exploits || [];
                exploits2 = vuln2.exploits || [];
                return parseInt(exploits1.length) - parseInt(exploits2.length);
            });
            sortIconExploits = iconSortAsc;
            sortFunctionExploits = "reorderVulns(3, false)";
        }
        else {
            vulns = vulns.sort(function (vuln1, vuln2) {
                exploits1 = vuln1.exploits || [];
                exploits2 = vuln2.exploits || [];
                return parseInt(exploits2.length) - parseInt(exploits1.length);
            });
            sortIconExploits = iconSortDesc;
            sortFunctionExploits = "reorderVulns(3, true)";
        }
    }

    vulns_html = '<table class="table table-sm table-rounded table-striped">';
    vulns_html += '<thead class="bg-darker">';
    vulns_html += '<tr>'
    vulns_html += `<th onclick="${sortFunctionCVEID}">CVE-ID&nbsp;&nbsp;${sortIconCVEID}</th>`;
    vulns_html += `<th onclick="${sortFunctionCVSS}">CVSS&nbsp;&nbsp;${sortIconCVSS}</th>`;
    vulns_html += '<th>Description</th>'
    vulns_html += `<th onclick="${sortFunctionExploits}">Exploit&nbsp;&nbsp;${sortIconExploits}</th>`;
    vulns_html += "</tr></thead>";
    vulns_html += "<tbody>";
    vulns_html += "<tr></<tr>";  // make striping start with white
    var exploits, cvss;

    for (var i = 0; i < vulns.length; i++) {
        vulns_html += `<tr>`;
        vulns_html += `<td class="text-nowrap pr-2"><a href="${vulns[i]["href"]}" target="_blank" style="color: inherit;"><i class="fa-solid fa-up-right-from-square"></i>&nbsp;&nbsp;${vulns[i]["id"]}</td>`;

        cvss = parseFloat(vulns[i].cvss);
        if (cvss >= 9.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-critical text-center">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 9.0 && cvss >= 7.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-high text-center">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 7.0 && cvss >= 4.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-medium text-center">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 4.0 && cvss >= 0.1)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-low text-center">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;

        vulns_html += `<td>${vulns[i]["description"]}</td>`;

        exploits = [];
        if (vulns[i].exploits !== undefined) {
            for (var j = 0; j < vulns[i].exploits.length; j++)
                exploits.push(`<a href="${vulns[i].exploits[j]}" target="_blank" style="color: inherit;">${vulns[i].exploits[j]}</a>`);
        }
        vulns_html += `<td class="text-nowrap">${exploits.join("<br>")}</td>`;

        vulns_html += "</tr>"
    }
    vulns_html += "</tbody></table>";
    return vulns_html;
}

function searchVulns() {
    var query = $('#query').val();
    var url_query = "query=" + query;

    if (ignoreGeneralCpeVulns)
        url_query += "&ignore-general-cpe-vulns=true";

    $("#vulns").html('<div class="row mt-3 justify-content-center align-items-center"><h5 class="spinner-border text-primary" style="width: 3rem; height: 3rem"></h5></div>');
    curVulnData = {};

    $.get({
        url: "/search_vulns",
        data: url_query,
        success: function (vulns) {
            var vulns_html = "";
            if (Object.keys(vulns[query]).length) {
                if (typeof vulns[query] !== "object")
                    vulns_html = `<h5 class="text-danger text-center">${vulns[query]}</h5>`;
                else {
                    curVulnData = vulns;
                    vulns_html = createVulnsHtml(1, false);
                }
            } else {
                vulns_html = "<h5>No data available</h5>";
            }
            $("#vulns").html(vulns_html);
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;

            $("#vulns").html(`<h5 class="text-danger text-center">${errorMsg}</h5>`);
        }
    })
}

function reorderVulns(sortColumnIdx, asc) {
    vulns_html = createVulnsHtml(sortColumnIdx, asc);
    $("#vulns").html(vulns_html);
}

function ignoreGeneralVulnsToggle() {
    ignoreGeneralCpeVulns = !ignoreGeneralCpeVulns;
    $("#vulns").html('');
    curVulnData = {};
}

// enables the user to press return on the query text field to make the query
$("#query").keypress(function (event) {
    var keycode = (event.keyCode ? event.keyCode : event.which);
    if (keycode == "13")
        $("#searchVulnsButton").click();
});