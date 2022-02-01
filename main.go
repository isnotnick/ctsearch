package main

import (
	"bytes"
	"database/sql"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

//	Struct definitions
type PerCAResult struct {
	CertCount int 			`json:"certcount"`
	CAIssuerDN string 		`json:"caissuerdn"`
	CAID int 				`json:"caid"`
}

type CertResult struct {
	CAID int 				`json:"caid"`
	CertID int 				`json:"certid"`
	CommonName string  		`json:"commonname"`
	SANCount int 			`json:"sancount"`
	NotBefore string 		`json:"notbefore"`
	NotAfter string 		`json:"notafter"`
	CertType string 		`json:"certtype"`
	ValType string 			`json:"valtype"`
	CABrand string 			`json:"cabrand"`
}

type CertExport struct {
	CAID int 				`json:"caid"`
	CertID int 				`json:"certid"`
	CommonName string  		`json:"commonname"`
	SANEntries string  		`json:"sanentries"`
	SANCount int 			`json:"sancount"`
	NotBefore string 		`json:"notbefore"`
	NotAfter string 		`json:"notafter"`
	CertType string 		`json:"certtype"`
	ValType string 			`json:"valtype"`
	CABrand string 			`json:"cabrand"`
}

// individual cert

var dbPG *sqlx.DB

//go:embed templates/*
var f embed.FS

func main() {
	router := gin.Default()

	//	Load HTML templates
	templateEmbed := template.Must(template.New("").ParseFS(f, "templates/*.html"))
	router.SetHTMLTemplate(templateEmbed)

	// Index route
	router.GET("/", indexPage)

	// Page routes
	router.GET("/domainsearch", domainSearch)
	router.GET("/domainsearch/ca/:caid/:domainName", domainSearchPerCA)
	router.GET("/domainsearch/exportcsv/:domainName", fetchValidCertsJSON)

	// Static routes for 'assets'
	router.StaticFile("/favicon.ico", "./assets/favicon.ico")
	router.Static("/assets", "./assets")

	// API routes - POSTed
	v1 := router.Group("/api/v1")
	{
		v1.POST("/domain/allvalid/:domainName", fetchValidCertsJSON)
		// get all with expired
		// get everything (expired? unexpired?) as CSV/XLSX?
		// get individual
		// get sumamry data JSON for charting
	}

	//	Open global polled sqlx db handle to crt.sh for CT queries
	connStr := "postgres://guest@crt.sh/certwatch?sslmode=verify-full&binary_parameters=yes"
	dbPG, _ = sqlx.Connect("postgres", connStr)
	err := dbPG.Ping()
	if err != nil {
		panic(err)
	
}
	router.Run("0.0.0.0:8080")
}

//	Main index/search page
func indexPage(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html",
		gin.H{
			"title": "CT Search",
		},
	)
}

func domainSearch(c *gin.Context) {
	caResults := []*PerCAResult{}
	certResults := []*CertResult{}

	domainQuery := c.Query("domainName")

	//	This query gets all certificates matching the provided FQDN, unexpires, de-duplicates and then groups by how many are issued per CA (ie per unique issuer DN)
	query := `WITH ci AS (
		SELECT min(sub.CERTIFICATE_ID) ID,
			   min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
			   array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
			   x509_commonName(sub.CERTIFICATE) COMMON_NAME,
			   x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
			   x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
			   encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER
			FROM (SELECT *
					  FROM certificate_and_identities cai
					  WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
						  AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')
						  AND coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')
						  AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'
						  AND NOT EXISTS (
							  SELECT 1
								  FROM certificate c2
								  WHERE x509_serialNumber(c2.CERTIFICATE) = x509_serialNumber(cai.CERTIFICATE)
									  AND c2.ISSUER_CA_ID = cai.ISSUER_CA_ID
									  AND c2.ID < cai.CERTIFICATE_ID
									  AND x509_tbscert_strip_ct_ext(c2.CERTIFICATE) = x509_tbscert_strip_ct_ext(cai.CERTIFICATE)
								  LIMIT 1
						  )
					  LIMIT 10000
				 ) sub
			GROUP BY sub.CERTIFICATE
	)
	SELECT ci.ISSUER_CA_ID CAID,
			ca.NAME CAIssuerDN,
			COUNT(ci.ID) CertCount
		FROM ci
				LEFT JOIN LATERAL (
					SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
						FROM ct_log_entry ctle
						WHERE ctle.CERTIFICATE_ID = ci.ID
				) le ON TRUE,
			 ca
		WHERE ci.ISSUER_CA_ID = ca.ID
		GROUP BY CAIssuerDN, CAID
		ORDER BY CertCount DESC;`

	query2 := `WITH ci AS (
		SELECT
			min(sub.CERTIFICATE_ID) ID,
			min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
			array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
			x509_commonName (sub.CERTIFICATE) COMMON_NAME,
			x509_notBefore (sub.CERTIFICATE) NOT_BEFORE,
			x509_notAfter (sub.CERTIFICATE) NOT_AFTER,
			encode(x509_serialNumber (sub.CERTIFICATE),
				'hex') SERIAL_NUMBER,
			certificate_type (sub.CERTIFICATE) CERT_TYPE,
			certificate_validation (sub.CERTIFICATE) VAL_TYPE
		FROM (
			SELECT
				*
			FROM
				certificate_and_identities cai
			WHERE
				plainto_tsquery('certwatch', $1) @@ identities (cai.CERTIFICATE)
				AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')
				AND coalesce(x509_notAfter (cai.CERTIFICATE),
					'infinity'::timestamp) >= date_trunc('year',
					now() AT TIME ZONE 'UTC')
				AND x509_notAfter (cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'
				AND NOT EXISTS (
					SELECT
						1
					FROM
						certificate c2
					WHERE
						x509_serialNumber (c2.CERTIFICATE) = x509_serialNumber (cai.CERTIFICATE)
						AND c2.ISSUER_CA_ID = cai.ISSUER_CA_ID
						AND c2.ID < cai.CERTIFICATE_ID
						AND x509_tbscert_strip_ct_ext (c2.CERTIFICATE) = x509_tbscert_strip_ct_ext (cai.CERTIFICATE)
					LIMIT 1)
			LIMIT 10000) sub
	GROUP BY
		sub.CERTIFICATE
	)
	SELECT
		ci.ISSUER_CA_ID CAID,
		COALESCE(ci.COMMON_NAME, 'No CN') CommonName,
		cardinality (ci.NAME_VALUES) SANCount,
		ci.ID CertID,
		ci.NOT_BEFORE NotBefore,
		ci.NOT_AFTER NotAfter,
		ci.CERT_TYPE CertType,
		ci.VAL_TYPE ValType,
		COALESCE(ccadb.CA_OWNER, 'Unknown') CABrand
	FROM
		ci
		LEFT JOIN LATERAL (
			SELECT
				min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
			FROM
				ct_log_entry ctle
			WHERE
				ctle.CERTIFICATE_ID = ci.ID) le ON TRUE, ca
		LEFT JOIN LATERAL (
			SELECT
				cc.CA_OWNER
			FROM
				ca_certificate cac,
				ccadb_certificate cc
			WHERE
				ca.ID = cac.CA_ID
				AND cac.CERTIFICATE_ID = cc.CERTIFICATE_ID
			LIMIT 1) ccadb ON TRUE
	WHERE
		ci.ISSUER_CA_ID = ca.ID
	ORDER BY
		le.ENTRY_TIMESTAMP DESC NULLS LAST;`

	err := dbPG.Select(&caResults, query, domainQuery)
	if err != nil {
		fmt.Println("Error with grouped-by-ca query: ", err)
	}

	err = dbPG.Select(&certResults, query2, domainQuery)
	if err != nil {
		fmt.Println("Error with per-cert-list query: ", err)
	}


	resultsSize := len(certResults)

	// Output the results of per-CA, and then the page will ajax-load pages of the individual results
	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs",
			},
		)
	}

	c.HTML(http.StatusOK, "mainresults.html",
		gin.H{
			"PerCAResults": caResults,
			"CertResultsList": certResults,
			"PageTitle":  "CT Search Results",
			"DomainName": domainQuery,
			"ResultSize": resultsSize,
		},
	)
}

func domainSearchPerCA(c *gin.Context) {
	certResults := []*CertResult{}

	domainQuery := c.Param("domainName")
	caID := c.Param("caid")
	var caName string

	query := `WITH ci AS MATERIALIZED (
		SELECT sub.CERTIFICATE_ID ID,
			   sub.ISSUER_CA_ID,
			   array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
			   x509_commonName(sub.CERTIFICATE) COMMON_NAME,
			   x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
			   x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
			   encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER,
			   certificate_type (sub.CERTIFICATE) CERT_TYPE,
				certificate_validation (sub.CERTIFICATE) VAL_TYPE
			FROM (SELECT *
					  FROM certificate_and_identities cai
					  WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
						  AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')
						  AND coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp) >= date_trunc('year', now() AT TIME ZONE 'UTC')
						  AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'
						  AND NOT EXISTS (
							  SELECT 1
								  FROM certificate c2
								  WHERE x509_serialNumber(c2.CERTIFICATE) = x509_serialNumber(cai.CERTIFICATE)
									  AND c2.ISSUER_CA_ID = cai.ISSUER_CA_ID
									  AND c2.ID < cai.CERTIFICATE_ID
									  AND x509_tbscert_strip_ct_ext(c2.CERTIFICATE) = x509_tbscert_strip_ct_ext(cai.CERTIFICATE)
								  LIMIT 1
						  )
					  LIMIT 10000
				 ) sub
		GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE
	)
	SELECT ci.ISSUER_CA_ID CAID,
			COALESCE(ci.COMMON_NAME, 'No CN') CommonName,
			cardinality (ci.NAME_VALUES) SANCount,
			ci.ID CertID,
			ci.NOT_BEFORE NotBefore,
			ci.NOT_AFTER NotAfter,
			ci.CERT_TYPE CertType,
			ci.VAL_TYPE ValType
		FROM ci
		WHERE ci.ISSUER_CA_ID = $2
		ORDER BY NOT_BEFORE DESC;`

	query2 := `SELECT
	x509_issuerName (c.CERTIFICATE) ISSUER_NAME
FROM
	ca_certificate cac,
	certificate c
	LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
WHERE
	cac.CA_ID = $1
	AND cac.CERTIFICATE_ID = c.ID
GROUP BY
	ISSUER_NAME;`
	
	err := dbPG.Select(&certResults, query, domainQuery, caID)
	if err != nil {
		fmt.Println("Error with per-ca-cert-list query: ", err)
	}

	err = dbPG.Get(&caName, query2, caID)
	if err != nil {
		fmt.Println("Error with ca name query: ", err)
	}

	resultsSize := len(certResults)

	// Output the results of per-CA, and then the page will ajax-load pages of the individual results
	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs",
			},
		)
	}

	c.HTML(http.StatusOK, "percaresults.html",
		gin.H{
			"CertResultsList": certResults,
			"PageTitle":  "CT Search Results",
			"DomainName": domainQuery,
			"ResultSize": resultsSize,
			"CAName": caName,
		},
	)
}



func fetchValidCertsJSON(c *gin.Context) {
	//	This query fetches all unexpired (at time of query) certs, de-duplicated and with simplified output fields
	query := `WITH ci AS (
		SELECT
			min(sub.CERTIFICATE_ID) ID,
			min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
			array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
			x509_commonName (sub.CERTIFICATE) COMMON_NAME,
			x509_notBefore (sub.CERTIFICATE) NOT_BEFORE,
			x509_notAfter (sub.CERTIFICATE) NOT_AFTER,
			encode(x509_serialNumber (sub.CERTIFICATE),
				'hex') SERIAL_NUMBER,
			certificate_type (sub.CERTIFICATE) CERT_TYPE,
			certificate_validation (sub.CERTIFICATE) VAL_TYPE
		FROM (
			SELECT
				*
			FROM
				certificate_and_identities cai
			WHERE
				plainto_tsquery('certwatch', $1) @@ identities (cai.CERTIFICATE)
				AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')
				AND coalesce(x509_notAfter (cai.CERTIFICATE),
					'infinity'::timestamp) >= date_trunc('year',
					now() AT TIME ZONE 'UTC')
				AND x509_notAfter (cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC'
				AND NOT EXISTS (
					SELECT
						1
					FROM
						certificate c2
					WHERE
						x509_serialNumber (c2.CERTIFICATE) = x509_serialNumber (cai.CERTIFICATE)
						AND c2.ISSUER_CA_ID = cai.ISSUER_CA_ID
						AND c2.ID < cai.CERTIFICATE_ID
						AND x509_tbscert_strip_ct_ext (c2.CERTIFICATE) = x509_tbscert_strip_ct_ext (cai.CERTIFICATE)
					LIMIT 1)
			LIMIT 10000) sub
	GROUP BY
		sub.CERTIFICATE
	)
	SELECT
		ci.ISSUER_CA_ID CAID,
		COALESCE(ci.COMMON_NAME, 'No CN') CommonName,
		array_to_string(ci.NAME_VALUES, ' ') SanEntries,
		cardinality (ci.NAME_VALUES) SANCount,
		ci.ID CertID,
		ci.NOT_BEFORE NotBefore,
		ci.NOT_AFTER NotAfter,
		ci.CERT_TYPE CertType,
		ci.VAL_TYPE ValType,
		COALESCE(ccadb.CA_OWNER, 'Unknown') CABrand
	FROM
		ci
		LEFT JOIN LATERAL (
			SELECT
				min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
			FROM
				ct_log_entry ctle
			WHERE
				ctle.CERTIFICATE_ID = ci.ID) le ON TRUE, ca
		LEFT JOIN LATERAL (
			SELECT
				cc.CA_OWNER
			FROM
				ca_certificate cac,
				ccadb_certificate cc
			WHERE
				ca.ID = cac.CA_ID
				AND cac.CERTIFICATE_ID = cc.CERTIFICATE_ID
			LIMIT 1) ccadb ON TRUE
	WHERE
		ci.ISSUER_CA_ID = ca.ID
	ORDER BY
		le.ENTRY_TIMESTAMP DESC NULLS LAST;`

	certResults := []*CertExport{}
	
	err := dbPG.Select(&certResults, query, c.Param("domainName"))
	if err != nil {
		fmt.Println("Error querying all certs for JSON: ", err)
	}

	if err != nil {
		c.HTML(http.StatusOK, "error.html",
			gin.H{
				"ErrorMessage": "Error querying CT logs",
			},
		)
	}

	b := &bytes.Buffer{}
	w := csv.NewWriter(b)

	if err = w.Write([]string{"Certificate ID", "Issuer ID", "Common Name", "SAN Entries", "SAN Count", "NotBefore", "NotAfter", "Certificate Type", "Validation Type", "CA Brand"}); err != nil {
		panic(err)
	}

	for _, thisCertificate := range certResults {
		var csvLine []string
		csvLine = append(csvLine, strconv.Itoa(thisCertificate.CertID))
		csvLine = append(csvLine, strconv.Itoa(thisCertificate.CAID))
		csvLine = append(csvLine, thisCertificate.CommonName)
		csvLine = append(csvLine, thisCertificate.SANEntries)
		csvLine = append(csvLine, strconv.Itoa(thisCertificate.SANCount))
		csvLine = append(csvLine, thisCertificate.NotBefore)
		csvLine = append(csvLine, thisCertificate.NotAfter)
		csvLine = append(csvLine, thisCertificate.CertType)
		csvLine = append(csvLine, thisCertificate.ValType)
		csvLine = append(csvLine, thisCertificate.CABrand)

		if err := w.Write(csvLine); err != nil {
			fmt.Println("Error writing line to csv:", err)
		}
	}
	w.Flush()

	if err := w.Error(); err != nil {
		fmt.Println(err)
	}
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Disposition", "attachment; filename=export-"+ c.Param("domainName") +".csv")
	c.Data(http.StatusOK, "text/csv", b.Bytes())



	//c.IndentedJSON(http.StatusOK, certResults)
	/*
	type CertExport struct {
	CAID int 				`json:"caid"`
	CertID int 				`json:"certid"`
	CommonName string  		`json:"commonname"`
	SANEntries string  		`json:"sanentries"`
	SANCount int 			`json:"sancount"`
	NotBefore string 		`json:"notbefore"`
	NotAfter string 		`json:"notafter"`
	CertType string 		`json:"certtype"`
	ValType string 			`json:"valtype"`
	CABrand string 			`json:"cabrand"`
	}*/
}



//	Helper functions

func jsonify(rows *sql.Rows) ([]string) {
	columns, err := rows.Columns()
	if err != nil {
		panic(err.Error())
	}

	values := make([]interface{}, len(columns))

	scanArgs := make([]interface{}, len(values))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	c := 0
	results := make(map[string]interface{})
	data := []string{}

	for rows.Next() {
		if c > 0 {
			data = append(data, ",")
		}

		err = rows.Scan(scanArgs...)
		if err != nil {
			panic(err.Error())
		}

		for i, value := range values {
			switch value.(type) {
				case nil:
					results[columns[i]] = nil

				case []byte:
					s := string(value.([]byte))
					x, err := strconv.Atoi(s)

					if err != nil {
						results[columns[i]] = s
					} else {
						results[columns[i]] = x
					}


				default:
					results[columns[i]] = value
			}
		}

		b, _ := json.Marshal(results)
		data = append(data, strings.TrimSpace(string(b)))
		c++
	}

	return data
}

func PrettyPrint(v interface{}) (err error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
			fmt.Println(string(b))
	}
	return
}