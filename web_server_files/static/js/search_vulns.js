
var curVulnData = {};
var exploit_url_show_max_length = 55, exploit_url_show_max_length_md = 42;
var ignoreGeneralCpeVulns = false, onlyShowEDBExploits = false;
var iconUnsorted = '<i class="fa-solid fa-sort"></i>';
var iconSortDesc = '<i class="fa-solid fa-sort-down"></i>';
var iconSortAsc = '<i class="fa-solid fa-sort-up"></i>';
var curSortColIdx = 1, curSortColAsc = false;
var copyButtonsHTML = `<div class="row mt-3 justify-content-center align-items-center"><div class="col-6 text-center justify-content-center align-items-center"><button type="button" class="btn btn-info" name="copyCSVButton" id="copyCSVButton" onclick="copyToClipboardCSV()"><i style="font-size: 1rem" class="fa-solid fa-clipboard"></i>&nbsp;&nbsp;Copy to Clipboard (CSV)</button></div><div class="col-6 text-center justify-content-center align-items-center"><button type="button" class="btn btn-info" name="copyMarkdownTableButton" id="copyMarkdownTableButton" onclick="copyToClipboardMarkdownTable()"><i style="font-size: 1rem" class="fa-solid fa-clipboard"></i>&nbsp;&nbsp;Copy to Clipboard (Markdown Table)</button></div></div>`;

function htmlEntities(text) {
    return text.replace(/[\u00A0-\u9999<>\&"']/g, function (i) {
        return '&#' + i.charCodeAt(0) + ';';
    });
}

function reduceToEDBUrls(allUrls) {
    var edb_urls = [];
    for (var i = 0; i < allUrls.length; i++) {
        if (allUrls[i].startsWith('https://www.exploit-db.com/exploits/'))
            edb_urls.push(allUrls[i]);
    }
    return edb_urls;
}

function getCurrentVulnsSorted() {
    var vulns = Object.values(curVulnData);
    if (curSortColIdx == 0) {  // CVE-ID
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return vuln1.id.localeCompare(vuln2.id);
            }).reverse();

        }
    }
    else if (curSortColIdx == 1) {  // CVSS
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln1.cvss) - parseFloat(vuln2.cvss);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                return parseFloat(vuln2.cvss) - parseFloat(vuln1.cvss);
            });
        }
    }
    else if (curSortColIdx == 3) {  // Exploits
        if (curSortColAsc) {
            return vulns.sort(function (vuln1, vuln2) {
                var exploits1 = vuln1.exploits || [];
                var exploits2 = vuln2.exploits || [];

                if (onlyShowEDBExploits) {
                    exploits1 = reduceToEDBUrls(exploits1);
                    exploits2 = reduceToEDBUrls(exploits2);
                }

                return parseInt(exploits1.length) - parseInt(exploits2.length);
            });
        }
        else {
            return vulns.sort(function (vuln1, vuln2) {
                var exploits1 = vuln1.exploits || [];
                var exploits2 = vuln2.exploits || [];

                if (onlyShowEDBExploits) {
                    exploits1 = reduceToEDBUrls(exploits1);
                    exploits2 = reduceToEDBUrls(exploits2);
                }

                return parseInt(exploits2.length) - parseInt(exploits1.length);
            });
        }
    }
}

function createVulnsHtml() {
    var sortIconCVEID = iconUnsorted, sortFunctionCVEID = "reorderVulns(0, false)";
    var sortIconCVSS = iconUnsorted, sortFunctionCVSS = "reorderVulns(1, false)";
    var sortIconExploits = iconUnsorted, sortFunctionExploits = "reorderVulns(3, false)";

    // retrieve and sort vulns
    var vulns = getCurrentVulnsSorted();
    if (curSortColIdx == 0) {  // CVE-ID
        if (curSortColAsc) {
            sortIconCVEID = iconSortAsc;
            sortFunctionCVEID = "reorderVulns(0, false)";
        }
        else {
            sortIconCVEID = iconSortDesc;
            sortFunctionCVEID = "reorderVulns(0, true)";
        }
    }
    else if (curSortColIdx == 1) {  // CVSS
        if (curSortColAsc) {
            sortIconCVSS = iconSortAsc;
            sortFunctionCVSS = "reorderVulns(1, false)";
        }
        else {
            sortIconCVSS = iconSortDesc;
            sortFunctionCVSS = "reorderVulns(1, true)";
        }
    }
    else if (curSortColIdx == 3) {  // Exploits
        if (curSortColAsc) {
            sortIconExploits = iconSortAsc;
            sortFunctionExploits = "reorderVulns(3, false)";
        }
        else {
            sortIconExploits = iconSortDesc;
            sortFunctionExploits = "reorderVulns(3, true)";
        }
    }

    vulns_html = '<table class="table table-sm table-rounded table-borderless">';
    vulns_html += '<thead>';
    vulns_html += '<tr>'
    vulns_html += `<th onclick="${sortFunctionCVEID}" style="white-space: nowrap;">CVE-ID&nbsp;&nbsp;${sortIconCVEID}</th>`;
    vulns_html += `<th onclick="${sortFunctionCVSS}" style="white-space: nowrap;">CVSS&nbsp;&nbsp;${sortIconCVSS}</th>`;
    vulns_html += '<th>Description</th>'
    vulns_html += `<th onclick="${sortFunctionExploits}" style="white-space: nowrap;">Exploits&nbsp;&nbsp;${sortIconExploits}</th>`;
    vulns_html += "</tr></thead>";
    vulns_html += "<tbody>";
    var exploits, cvss, exploit_url_show;

    for (var i = 0; i < vulns.length; i++) {
        vulns_html += `<tr>`;
        vulns_html += `<td class="text-nowrap pr-2"><a href="${htmlEntities(vulns[i]["href"])}" target="_blank" style="color: inherit;">${vulns[i]["id"]}&nbsp;&nbsp;<i class="fa-solid fa-up-right-from-square" style="font-size: 0.92rem"></i></a></td>`;

        var cvss_vector = vulns[i].cvss_vec;
        if (!cvss_vector.startsWith('CVSS'))
            cvss_vector = "CVSS:2.0/" + cvss_vector;

        cvss = parseFloat(vulns[i].cvss);
        if (cvss >= 9.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-critical text-center" data-toggle="tooltip" data-container="body" data-placement="bottom" data-html="true" data-original-title="<b>${cvss_vector}</b>" data-template="<div class='tooltip' role='tooltip'><div class='arrow'></div><div class='tooltip-inner tooltip-cvss'></div></div>">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 9.0 && cvss >= 7.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-high text-center" data-toggle="tooltip" data-container="body" data-placement="bottom" data-html="true" data-original-title="<b>${cvss_vector}</b>" data-template="<div class='tooltip' role='tooltip'><div class='arrow'></div><div class='tooltip-inner tooltip-cvss'></div></div>">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 7.0 && cvss >= 4.0)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-medium text-center" data-toggle="tooltip" data-placement="bottom" data-html="true" data-original-title="<b>${cvss_vector}</b>" data-template="<div class='tooltip' role='tooltip'><div class='arrow'></div><div class='tooltip-inner tooltip-cvss'></div></div>">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;
        else if (cvss < 4.0 && cvss >= 0.1)
            vulns_html += `<td class="text-nowrap"><div class="badge-pill badge-low text-center" data-toggle="tooltip" data-placement="bottom" data-html="true" data-original-title="<b>${cvss_vector}</b>" data-template="<div class='tooltip' role='tooltip'><div class='arrow'></div><div class='tooltip-inner tooltip-cvss'></div></div>">${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]})</div></td>`;

        vulns_html += `<td>${htmlEntities(vulns[i]["description"])}</td>`;
        exploits = [];
        if (vulns[i].exploits !== undefined) {
            for (var j = 0; j < vulns[i].exploits.length; j++) {
                if (onlyShowEDBExploits && !vulns[i].exploits[j].startsWith('https://www.exploit-db.com/exploits/'))
                    continue;

                exploit_url_show = vulns[i].exploits[j];
                if (exploit_url_show.length > exploit_url_show_max_length) {
                    exploit_url_show = exploit_url_show.substring(0, exploit_url_show_max_length - 2) + '...';
                }
                exploits.push(`<a href="${vulns[i].exploits[j].replace('"', '&quot;')}" target="_blank" style="color: inherit;">${htmlEntities(exploit_url_show)}</a>`);
            }
        }
        vulns_html += `<td class="text-nowrap">${exploits.join("<br>")}</td>`;
        vulns_html += "</tr>"
    }
    vulns_html += "</tbody></table>";
    return vulns_html;
}

function createVulnsMarkDownTable() {
    var vulns = getCurrentVulnsSorted();
    var vulns_md = "";
    var has_exploits = false;
    var exploit_url_show;

    for (var i = 0; i < vulns.length; i++) {
        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (!onlyShowEDBExploits || reduceToEDBUrls(vulns[i].exploits).length > 0) {
                has_exploits = true;
                break
            }
        }
    }

    if (has_exploits) {
        vulns_md = '|CVE|CVSS|Description|Exploits|\n';
        vulns_md += '|:---:|:---:|:---|:---|\n';
    }
    else {
        vulns_md = '|CVE|CVSS|Description|\n';
        vulns_md += '|:---:|:---:|:---|\n';
    }

    for (var i = 0; i < vulns.length; i++) {
        vulns_md += `|[${vulns[i]["id"]}](${htmlEntities(vulns[i]["href"])})|${vulns[i]["cvss"]}&nbsp;(v${vulns[i]["cvss_ver"]})|`;
        vulns_md += `${htmlEntities(vulns[i]["description"]).replaceAll('|', '&#124;')}|`;

        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            for (var j = 0; j < vulns[i].exploits.length; j++) {
                if (onlyShowEDBExploits && !vulns[i].exploits[j].startsWith('https://www.exploit-db.com/exploits/'))
                    continue;

                exploit_url_show = vulns[i].exploits[j];
                if (exploit_url_show.length > exploit_url_show_max_length_md) {
                    exploit_url_show = exploit_url_show.substring(0, exploit_url_show_max_length_md - 2) + '...';
                }
                vulns_md += `[${htmlEntities(exploit_url_show)}](${vulns[i].exploits[j]})<br>`;
            }
            if (has_exploits) {
                vulns_md = vulns_md.substring(0, vulns_md.length - 4);  // remove last <br>
                vulns_md += "|";
            }
        }
        else if (has_exploits)
            vulns_md += "|";

        vulns_md += '\n'
    }

    return vulns_md;
}

function createVulnsCSV() {
    var vulns = getCurrentVulnsSorted();
    var vulns_csv = "";
    var has_exploits = false;

    for (var i = 0; i < vulns.length; i++) {
        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (!onlyShowEDBExploits || reduceToEDBUrls(vulns[i].exploits).length > 0) {
                has_exploits = true;
                break
            }
        }
    }

    if (has_exploits)
        vulns_csv = 'CVE,CVSS,Description,Exploits\n';
    else
        vulns_csv = 'CVE,CVSS,Description\n';

    for (var i = 0; i < vulns.length; i++) {
        vulns_csv += `${vulns[i]["id"]},${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]}),`;
        vulns_csv += `"${vulns[i]["description"].replaceAll('"', '""')}"`;

        if (has_exploits)
            vulns_csv += ",";

        if (has_exploits && vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (onlyShowEDBExploits)
                vulns_csv += `"${reduceToEDBUrls(vulns[i].exploits).join(", ")}"`;
            else
                vulns_csv += `"${vulns[i].exploits.join(", ")}"`;
        }
        vulns_csv += '\n'
    }

    return vulns_csv;
}


function searchVulns() {
    var query = $('#query').val();
    var queryEnc = encodeURIComponent(query);
    var url_query = "query=" + queryEnc;
    var new_url = window.location.pathname + '?query=' + queryEnc;

    if (ignoreGeneralCpeVulns) {
        url_query += "&ignore-general-cpe-vulns=true";
        new_url += '&general-vulns=false';
    }

    history.pushState({}, null, new_url);  // update URL
    $("#searchVulnsButton").attr("disabled", true);
    $("#vulns").html('<div class="row mt-3 justify-content-center align-items-center"><h5 class="spinner-border text-primary" style="width: 3rem; height: 3rem"></h5></div>');
    curSortColIdx = 1;
    curSortColAsc = false;
    curVulnData = {};

    $.get({
        url: "/search_vulns",
        data: url_query,
        success: function (vulns) {
            var vulns_html = "";
            if (typeof vulns[query] !== "object")
                vulns_html = `<h5 class="text-danger text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
            else {
                cpe = vulns[query]['cpe'];
                var alt_queries_start_idx = 1;
                if (cpe != undefined) {
                    curVulnData = vulns[query]['vulns'];
                    if (Object.keys(curVulnData).length > 0) {
                        vulns_html = createVulnsHtml();
                        vulns_html = `<div class="row mt-2"><div class="col text-center"><h5 style="font-size: 1.05rem;">${htmlEntities(query)} (${htmlEntities(cpe)})</h5></div></div>` + vulns_html;
                        vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
                        vulns_html += copyButtonsHTML;
                    }
                    else {
                        vulns_html = `<div class="row mt-2"><div class="col text-center"><h5 style="font-size: 1.05rem;">${htmlEntities(query)} (${htmlEntities(cpe)})</h5></div></div><br><h5 class="text-center">No known vulnerabilities could be found.</h5>`;
                    }
                }
                else {
                    alt_queries_start_idx = 0;
                    vulns_html = `<h5 class="text-danger text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
                }

                if (vulns[query].hasOwnProperty('pot_cpes') && vulns[query]["pot_cpes"].length > 0 + alt_queries_start_idx) {
                    vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
                    vulns_html += `<div class="row mx-2"><div class="col"><h5>Related queries:</h5></div></div>`;
                    vulns_html += `<div class="row mx-2"><div class="col"><ul>`;
                    for (var i = alt_queries_start_idx; i < vulns[query]["pot_cpes"].length; i++) {
                        vulns_html += `<li><a href="/?query=${htmlEntities(vulns[query]["pot_cpes"][i][0])}">${htmlEntities(vulns[query]["pot_cpes"][i][0])}</a></li>`
                    }
                    vulns_html += `</ul></div></div>`;
                }
            }
            $("#vulns").html(vulns_html);
            $("#searchVulnsButton").removeAttr("disabled");
        },
        error: function (jXHR, textStatus, errorThrown) {
            var errorMsg;
            if ("responseText" in jXHR)
                errorMsg = jXHR["responseText"];
            else
                errorMsg = errorThrown;

            $("#vulns").html(`<h5 class="text-danger text-center">${htmlEntities(errorMsg)}</h5>`);
            $("#searchVulnsButton").removeAttr("disabled");
        }
    })
}

function reorderVulns(sortColumnIdx, asc) {
    curSortColIdx = sortColumnIdx;
    curSortColAsc = asc;
    vulns_html = createVulnsHtml();
    vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
    vulns_html += copyButtonsHTML;
    $("#vulns").html(vulns_html);
}

function ignoreGeneralVulnsToggle() {
    ignoreGeneralCpeVulns = !ignoreGeneralCpeVulns;
    $("#vulns").html('');
    curVulnData = {};
}

function onlyEDBExploitsToggle() {
    onlyShowEDBExploits = !onlyShowEDBExploits;
    if (!$.isEmptyObject(curVulnData)) {
        var vulns_html = createVulnsHtml();
        vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
        vulns_html += copyButtonsHTML;
        $("#vulns").html(vulns_html);
    }
}

function copyToClipboardMarkdownTable() {
    navigator.clipboard.writeText(createVulnsMarkDownTable());
    $("#copyMarkdownTableButton").html('<i style="font-size: 1rem" class="fa-solid fa-clipboard-check"></i>&nbsp;&nbsp;Copied Markdown Table to Clipboard');
    $("#copyMarkdownTableButton").attr('class', 'btn btn-success');
}

function copyToClipboardCSV() {
    navigator.clipboard.writeText(createVulnsCSV());
    $("#copyCSVButton").html('<i style="font-size: 1rem" class="fa-solid fa-clipboard-check"></i>&nbsp;&nbsp;Copied CSV to Clipboard');
    $("#copyCSVButton").attr('class', 'btn btn-success');
}

function init() {
    if (location.search !== '' && location.search !== '?') {
        var url = new URL(document.location.href);
        var params = new URLSearchParams(url.search);
        var init_query = params.get('query');
        if (init_query !== null)
            $('#query').val(htmlEntities(init_query));

        var show_general_vulns = params.get('general-vulns');
        if (String(show_general_vulns).toLowerCase() === "false")
            $('#toggleIgnoreGeneralCpeVulns').click();

        if (init_query !== null)
            $("#searchVulnsButton").click();
    }
}

// enables the user to press return on the query text field to make the query
$("#query").keypress(function (event) {
    var keycode = (event.keyCode ? event.keyCode : event.which);
    if (keycode == "13" && $("#searchVulnsButton").attr("disabled") === undefined)
        $("#searchVulnsButton").click();
});

// check for existing query in URL
init();

// activate tooltips
$(document).ready(function () {
    $("body").tooltip({ selector: '[data-toggle=tooltip]' });
});
