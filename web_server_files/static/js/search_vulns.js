
var curVulnData = {};
var exploit_url_show_max_length = 55, exploit_url_show_max_length_md = 42;
var ignoreGeneralCpeVulns = false, onlyShowEDBExploits = false, isGoodCpe = true;
var iconUnsorted = '<i class="fa-solid fa-sort"></i>';
var iconSortDesc = '<i class="fa-solid fa-sort-down"></i>';
var iconSortAsc = '<i class="fa-solid fa-sort-up"></i>';
var curSortColIdx = 1, curSortColAsc = false;

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
        if (ignoreGeneralCpeVulns && vulns[i].vuln_match_reason == "general_cpe")
            continue;

        if (vulns[i].vuln_match_reason == "general_cpe")
            vulns_html += `<tr class="uncertain-vuln">`;
        else
            vulns_html += `<tr>`;

        vulns_html += `<td class="text-nowrap pr-2"><a href="${htmlEntities(vulns[i]["href"])}" target="_blank" style="color: inherit;">${vulns[i]["id"]}&nbsp;&nbsp;<i class="fa-solid fa-up-right-from-square" style="font-size: 0.92rem"></i></a>`;
        if (vulns[i].vuln_match_reason == "general_cpe")
            vulns_html += `<br><center><i class="far fa-question-circle" style="color: #FF4F00;" data-toggle="tooltip" data-template="<div class='tooltip' role='tooltip'><div class='arrow'></div><div class='tooltip-inner tooltip-info'></div></div>" data-placement="bottom" data-original-title="This vulnerability affects the queried software in general and could be a false positive."></i></center>`;
        vulns_html += "</td>";

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
        vulns_html += "</tr>";
    }
    vulns_html += "</tbody></table>";
    return vulns_html;
}

function changeExportFields () {
    var exportFields = [];
    var selectedFields = $('#select-export-fields').val();
    // can't use IDs, b/c selectpicker generates different HTML
    selectedFields.forEach(fieldName => {
        if (fieldName == "CVE-ID")
            exportFields.push('cve');
        else if (fieldName == "CVSS Score")
            exportFields.push('cvss');
        else if (fieldName == "Description")
            exportFields.push('descr');
        else if (fieldName == "Exploits")
            exportFields.push('expl');
    });
    localStorage.setItem('exportFields', JSON.stringify(exportFields));
}

function createResultProcessingHtml() {
    var selectedExportOptions = JSON.parse(localStorage.getItem('exportFields'));
    var fieldOptionsHTML = "";

    if (selectedExportOptions.includes("cve"))
        fieldOptionsHTML += `<option selected>CVE-ID</option>`;
    else
        fieldOptionsHTML += `<option>CVE-ID</option>`;

    if (selectedExportOptions.includes("cvss"))
        fieldOptionsHTML += `<option selected>CVSS Score</option>`;
    else
        fieldOptionsHTML += `<option>CVSS Score</option>`;

    if (selectedExportOptions.includes("descr"))
        fieldOptionsHTML += `<option selected>Description</option>`;
    else
        fieldOptionsHTML += `<option>Description</option>`;

    if (selectedExportOptions.includes("expl"))
        fieldOptionsHTML += `<option selected>Exploits</option>`;
    else
        fieldOptionsHTML += `<option>Exploits</option>`;

    return `
        <div class="d-flex p-0 justify-content-center">
            <div class="form-group m-0 p-0 pr-2 justify-content-center align-self-center">
                <select id="select-export-vulns" name="select-export-vulns" class="selectpicker form-control" data-selected-text-format="static" multiple data-actions-box="true" title=" Select CVEs (default: all)" onChange="resetCopyToClipboardMarkdownButton(); resetCopyToClipboardCSVButton();">
                    ${getCurrentVulnsSorted().map(vuln => '<option>' + vuln.id + ' (' + vuln.cvss + ')' + '</option>').join('\n')}
                </select>
            </div>
            <div class="form-group m-0 p-0 pr-5 justify-content-center align-self-center">
                <select id="select-export-fields" name="select-export-fields" class="selectpicker form-control" multiple data-selected-text-format="count > 3" data-actions-box="true" title="Select Fields (default: all)" onChange="resetCopyToClipboardMarkdownButton(); resetCopyToClipboardCSVButton(); changeExportFields()">
                    ${fieldOptionsHTML}
                </select>
            </div>
            <div class="align-self-center pr-2"><button type="button"
                class="btn btn-info" name="copyCSVButton" id="copyCSVButton"
                onclick="copyToClipboardCSV()"><i style="font-size: 1rem"
                    class="fa-solid fa-clipboard"></i>&nbsp;&nbsp;Copy to Clipboard (CSV)</button></div>
            <div class="align-self-center"><button type="button"
                class="btn btn-info" name="copyMarkdownTableButton" id="copyMarkdownTableButton"
                onclick="copyToClipboardMarkdownTable()"><i style="font-size: 1rem"
                    class="fa-solid fa-clipboard"></i>&nbsp;&nbsp;Copy to Clipboard (Markdown
                Table)</button></div>
        </div>
    `;
}

function createVulnsMarkDownTable() {
    var selectedVulns = $('#select-export-vulns').val().map(vuln => vuln.split(' ')[0]);
    var selectedFields = $('#select-export-fields').val();
    var vulns = getCurrentVulnsSorted();
    var vulns_md = "";
    var has_exploits = false, cur_vuln_has_exploits = false;
    var exploit_url_show;

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;
        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (!onlyShowEDBExploits || reduceToEDBUrls(vulns[i].exploits).length > 0) {
                has_exploits = true;
                break
            }
        }
    }

    if (selectedFields.length > 0) {
        var table_row1 = "|", table_row2 = "|";
        selectedFields.forEach(fieldName => {
            if (fieldName == "CVE-ID") {
                table_row1 += 'CVE|';
                table_row2 += ':---:|';
            }
            else if (fieldName == "CVSS Score") {
                table_row1 += 'CVSS|';
                table_row2 += ':---:|';
            }
            else if (fieldName == "Description") {
                table_row1 += 'Description|';
                table_row2 += ':---|';
            }
            else if (fieldName == "Exploits" && has_exploits) {
                table_row1 += 'Exploits|';
                table_row2 += ':---|';
            }
        })
        vulns_md = table_row1 + '\n' + table_row2 + '\n';
    }
    else {
        if (has_exploits) {
            vulns_md = '|CVE|CVSS|Description|Exploits|\n';
            vulns_md += '|:---:|:---:|:---|:---|\n';
        }
        else {
            vulns_md = '|CVE|CVSS|Description|\n';
            vulns_md += '|:---:|:---:|:---|\n';
        }
    }

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;

        cur_vuln_has_exploits = false;
        vulns_md += '|';
        if (selectedFields.length < 1 || selectedFields.includes('CVE-ID'))
            vulns_md += `[${vulns[i]["id"]}](${htmlEntities(vulns[i]["href"])})|`
        if (selectedFields.length < 1 || selectedFields.includes('CVSS Score'))
            vulns_md += `${vulns[i]["cvss"]}&nbsp;(v${vulns[i]["cvss_ver"]})|`;
        if (selectedFields.length < 1 || selectedFields.includes('Description')) {
            var description = htmlEntities(vulns[i]["description"].trim());
            description = description.replaceAll('\n', '<br>');
            description = description.replaceAll('|', '&#124;');
            vulns_md += `${description}|`;
        }

        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0 && (selectedFields.length < 1 || selectedFields.includes('Exploits'))) {
            for (var j = 0; j < vulns[i].exploits.length; j++) {
                if (onlyShowEDBExploits && !vulns[i].exploits[j].startsWith('https://www.exploit-db.com/exploits/'))
                    continue;

                exploit_url_show = vulns[i].exploits[j];
                if (exploit_url_show.length > exploit_url_show_max_length_md) {
                    exploit_url_show = exploit_url_show.substring(0, exploit_url_show_max_length_md - 2) + '...';
                }
                vulns_md += `[${htmlEntities(exploit_url_show)}](${vulns[i].exploits[j]})<br>`;
                cur_vuln_has_exploits = true;
            }
            if (cur_vuln_has_exploits) {
                vulns_md = vulns_md.substring(0, vulns_md.length - 4);  // remove last <br>
                vulns_md += "|";
            }
            else if (has_exploits)
                vulns_md += "|";
        }
        else if (has_exploits && (selectedFields.length < 1 || selectedFields.includes('Exploits')))
            vulns_md += "|";

        vulns_md += '\n'
    }

    return vulns_md;
}

function createVulnsCSV() {
    var selectedVulns = $('#select-export-vulns').val().map(vuln => vuln.split(' ')[0]);
    var selectedFields = $('#select-export-fields').val();
    var vulns = getCurrentVulnsSorted();
    var vulns_csv = "";
    var has_exploits = false;

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;
        if (vulns[i].exploits !== undefined && vulns[i].exploits.length > 0) {
            if (!onlyShowEDBExploits || reduceToEDBUrls(vulns[i].exploits).length > 0) {
                has_exploits = true;
                break
            }
        }
    }

    if (selectedFields.length > 0) {
        selectedFields.forEach(fieldName => {
            if (fieldName == "CVE-ID")
                vulns_csv += 'CVE,';
            else if (fieldName == "CVSS Score")
                vulns_csv += 'CVSS,';
            else if (fieldName == "Description")
                vulns_csv += 'Description,';
            else if (fieldName == "Exploits" && has_exploits)
                vulns_csv += 'Exploits,';
        })
        vulns_csv = vulns_csv.slice(0, -1) + '\n';
    }
    else {
        if (has_exploits)
            vulns_csv = 'CVE,CVSS,Description,Exploits\n';
        else
            vulns_csv = 'CVE,CVSS,Description\n';
    }

    for (var i = 0; i < vulns.length; i++) {
        if (selectedVulns.length > 0 && !selectedVulns.includes(vulns[i]["id"]))
            continue;

        if (selectedFields.length < 1 || selectedFields.includes('CVE-ID'))
            vulns_csv += `${vulns[i]["id"]},`
        if (selectedFields.length < 1 || selectedFields.includes('CVSS Score'))
            vulns_csv += `${vulns[i]["cvss"]} (v${vulns[i]["cvss_ver"]}),`;
        if (selectedFields.length < 1 || selectedFields.includes('Description'))
            vulns_csv += `"${vulns[i]["description"].replaceAll('"', '""')}",`;


        if (vulns_csv.length > 0 && (!has_exploits || (selectedFields.length > 0 && !selectedFields.includes('Exploits'))))
            vulns_csv = vulns_csv.slice(0, -1);

        if (has_exploits && vulns[i].exploits !== undefined && vulns[i].exploits.length > 0 && (selectedFields.length < 1 || selectedFields.includes('Exploits'))) {
            if (onlyShowEDBExploits)
                vulns_csv += `"${reduceToEDBUrls(vulns[i].exploits).join(", ")}"`;
            else
                vulns_csv += `"${vulns[i].exploits.join(", ")}"`;
        }
        vulns_csv += '\n'
    }

    return vulns_csv;
}


function buildTextualReprFromCPE(cpe) {
    var product_title, cpe_parts, product_type, cpe_condition = '';
    cpe_parts = cpe.split(":");
    cpe_condition = '';

    if (cpe_parts[2] == 'a')
        product_type = 'Software';
    else if (cpe_parts[2] == 'o')
        product_type = 'Operating System';
    else if (cpe_parts[2] == 'h')
        product_type = 'Hardware';

    cpe_parts[3] = cpe_parts[3][0].toUpperCase() + cpe_parts[3].substring(1);
    cpe_parts[4] = cpe_parts[4][0].toUpperCase() + cpe_parts[4].substring(1);
    if (cpe_parts[4].startsWith(cpe_parts[3]))
        cpe_parts[4] = cpe_parts[4].substring(cpe_parts[3].length).trim();
    if (cpe_parts[4].startsWith('_'))
        cpe_parts[4] = cpe_parts[4].substring(1);

    product_title = cpe_parts[3].split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';
    if (cpe_parts[4] && cpe_parts[4] != cpe_parts[3])
        product_title += cpe_parts[4].split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';

    if (cpe_parts[5] && cpe_parts[5] != '-' && cpe_parts[5] != '*')
        product_title += cpe_parts[5] + ' ';

    if (cpe_parts[6] && cpe_parts[6] != '-' && cpe_parts[6] != '*')
        product_title += cpe_parts[6] + ' ';

    cpe_parts.slice(7).forEach(cpe_part => {
        if (cpe_part && cpe_part != '-' && cpe_part != '*') {
            cpe_part = cpe_part[0].toUpperCase() + cpe_part.substring(1);
            cpe_condition += cpe_part.split('_').map(w => w[0].toUpperCase() + w.substring(1).toLowerCase()).join(' ') + ' ';
        }
    });

    product_title = product_title.trim();
    cpe_condition = cpe_condition.trim();

    if (cpe_condition)
        return product_type + ': ' + product_title + ' ' + '[' + cpe_condition + ']';

    return product_type + ': ' + product_title
}


function searchVulns() {
    var query = $('#query').val();
    var queryEnc = encodeURIComponent(query);
    var url_query = "query=" + queryEnc;
    var new_url = window.location.pathname + '?query=' + queryEnc;

    if (!isGoodCpe) {
        url_query += "&is-good-cpe=false";
        new_url += '&is-good-cpe=false';
    }
    isGoodCpe = true;  // reset for subsequent query that wasn't initiated via URL

    history.pushState({}, null, new_url);  // update URL
    $("#searchVulnsButton").attr("disabled", true);
    $("#search-display").html("");
    $("#process-results-display").html("");
    $("#related-queries-display").html("");
    $("#vulns").html('<div class="row mt-3 justify-content-center align-items-center"><h5 class="spinner-border text-primary" style="width: 3rem; height: 3rem"></h5></div>');
    curSortColIdx = 1;
    curSortColAsc = false;
    curVulnData = {};

    $.get({
        url: "/search_vulns",
        data: url_query,
        success: function (vulns) {
            var vulns_html = "", search_display_html = "", process_results_html = "", related_queries_html = "";
            if (typeof Object.values(vulns)[0] !== "object")
                search_display_html = `<h5 class="text-danger text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
            else {
                vulns = Object.values(vulns)[0]
                cpe = vulns['cpe'];
                if (cpe != undefined) {
                    curVulnData = vulns['vulns'];
                    if (Object.keys(curVulnData).length > 0) {
                        search_display_html = `<div class="row mt-2"><div class="col text-center"><h5 style="font-size: 1.05rem;">${htmlEntities(query)} (${htmlEntities(cpe)})</h5></div></div>`;
                        vulns_html = createVulnsHtml();
                        vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
                        process_results_html = createResultProcessingHtml();
                    }
                    else {
                        search_display_html = `<div class="row mt-2"><div class="col text-center"><h5 style="font-size: 1.05rem;">${htmlEntities(query)} (${htmlEntities(cpe)})</h5></div></div><br><h5 class="text-center">No known vulnerabilities could be found.</h5>`;
                    }
                }
                else {
                    search_display_html = `<h5 class="text-danger text-center">Warning: Could not find matching software for query '${htmlEntities(query)}'</h5>`;
                }

                if (vulns.hasOwnProperty('pot_cpes') && vulns["pot_cpes"].length > 0) {
                    var related_queries_html_li = "";
                    for (var i = 0; i < vulns["pot_cpes"].length; i++) {
                        if (cpe == null || !cpe.includes(vulns["pot_cpes"][i][0]))
                            related_queries_html_li += `<li><a href="/?query=${encodeURIComponent(htmlEntities(vulns["pot_cpes"][i][0]))}&is-good-cpe=false">${htmlEntities(vulns["pot_cpes"][i][0])}</a> &nbsp; &nbsp;(${htmlEntities(buildTextualReprFromCPE(vulns["pot_cpes"][i][0]))})</li>`
                    }

                    if (related_queries_html_li != "") {
                        related_queries_html = `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
                        related_queries_html += `<div class="row mx-2"><div class="col"><h5>Related queries:</h5></div></div>`;
                        related_queries_html += `<div class="row mx-2"><div class="col"><ul>`;
                        related_queries_html += related_queries_html_li;
                        related_queries_html += `</ul></div></div>`;
                    }
                }
            }

            $("#vulns").html(vulns_html);
            $("#search-display").html(search_display_html);
            $("#process-results-display").html(process_results_html);
            $("select").selectpicker();
            $("#related-queries-display").html(related_queries_html);
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
    $("#vulns").html(vulns_html);
    $("#process-results-display").html(createResultProcessingHtml());
    $("select").selectpicker();
}

function ignoreGeneralVulnsToggle() {
    if (ignoreGeneralCpeVulns)
        localStorage.setItem("ignoreGeneralCpeVulns", 'false');
    else
        localStorage.setItem("ignoreGeneralCpeVulns", 'true');
    ignoreGeneralCpeVulns = !ignoreGeneralCpeVulns;

    if (!$.isEmptyObject(curVulnData)) {
        var vulns_html = createVulnsHtml();
        vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
        $("#vulns").html(vulns_html);
        $("#process-results-display").html(createResultProcessingHtml());
        $("select").selectpicker();
    }
}

function onlyEDBExploitsToggle() {
    if (onlyShowEDBExploits)
        localStorage.setItem("onlyShowEDBExploits", 'false');
    else
        localStorage.setItem("onlyShowEDBExploits", 'true');
    onlyShowEDBExploits = !onlyShowEDBExploits;

    if (!$.isEmptyObject(curVulnData)) {
        var vulns_html = createVulnsHtml();
        vulns_html += `<hr style="height: 2px; border:none; border-radius: 10px 10px 10px 10px; background-color:#d7d4d4;"/>`;
        $("#vulns").html(vulns_html);
        $("#process-results-display").html(createResultProcessingHtml());
        $("select").selectpicker();
    }
}

function copyToClipboardMarkdownTable() {
    var selectedExportOptions = JSON.parse(localStorage.getItem('exportFields'));
    var selectFieldsTitle = "Select Fields (default: all)";
    if (selectedExportOptions.length > 0)
        selectFieldsTitle = selectedExportOptions.join(', ');

    navigator.clipboard.writeText(createVulnsMarkDownTable());
    $("#copyMarkdownTableButton").html('<i style="font-size: 1rem" class="fa-solid fa-clipboard-check"></i>&nbsp;&nbsp;Copied Markdown Table to Clipboard');
    $("#copyMarkdownTableButton").attr('class', 'btn btn-success');
}

function resetCopyToClipboardMarkdownButton() {
    $("#copyMarkdownTableButton").html('<i style="font-size: 1rem" class="fa-solid fa-clipboard"></i>&nbsp;&nbsp;Copy to Clipboard (Markdown Table)');
    $("#copyMarkdownTableButton").attr('class', 'btn btn-info');
}

function copyToClipboardCSV() {
    var selectedExportOptions = JSON.parse(localStorage.getItem('exportFields'));
    var selectFieldsTitle = "Select Fields (default: all)";
    if (selectedExportOptions.length > 0)
        selectFieldsTitle = selectedExportOptions.join(', ');

    navigator.clipboard.writeText(createVulnsCSV());
    $("#copyCSVButton").html('<i style="font-size: 1rem" class="fa-solid fa-clipboard-check"></i>&nbsp;&nbsp;Copied CSV to Clipboard');
    $("#copyCSVButton").attr('class', 'btn btn-success');
}

function resetCopyToClipboardCSVButton() {
    $("#copyCSVButton").html('<i style="font-size: 1rem" class="fa-solid fa-clipboard"></i>&nbsp;&nbsp;Copy to Clipboard (CSV)');
    $("#copyCSVButton").attr('class', 'btn btn-info');
}

function init() {
    if (location.search !== '' && location.search !== '?') {
        var url = new URL(document.location.href);
        var params = new URLSearchParams(url.search);
        var init_query = params.get('query');
        if (init_query !== null)
            $('#query').val(htmlEntities(init_query));

        var is_good_cpe = params.get('is-good-cpe');
        if (String(is_good_cpe).toLowerCase() === "false")
            isGoodCpe = false;

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

// activate tooltips
$(document).ready(function () {
    $("body").tooltip({ selector: '[data-toggle=tooltip]' });
});

// setup configuration from LocalStorage
if (localStorage.getItem('onlyShowEDBExploits') === null) {
    localStorage.setItem('onlyShowEDBExploits', 'false');
}
if (localStorage.getItem('ignoreGeneralCpeVulns') === null) {
    localStorage.setItem('ignoreGeneralCpeVulns', 'false');
}

if (localStorage.getItem('onlyShowEDBExploits') == 'true') {
    onlyShowEDBExploits = true;
    document.getElementById("toggleOnlyEDBExploits").checked = true;
}
if (localStorage.getItem('ignoreGeneralCpeVulns') == 'true') {
    ignoreGeneralCpeVulns = true;
    document.getElementById("toggleIgnoreGeneralCpeVulns").checked = true;
}

if (localStorage.getItem('exportFields') === null) {
    localStorage.setItem('exportFields', '[]');
}

// check for existing query in URL and insert its parameters
init();
