﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using System.Web;
using System.Collections.Specialized;
using FluentAssertions;
using System.Collections.Generic;
using Kentor.AuthServices.WebSso;
using Kentor.AuthServices.Tests.WebSSO;

namespace Kentor.AuthServices.Tests.WebSso
{
    [TestClass]
    public class Saml2BindingTests
    {
        [TestMethod]
        public void Saml2Binding_Get_ReturnsSaml2Postbinding()
        {
            var r = new HttpRequestData(
                "POST",
                new Uri("http://example.com"),
                "/ModulePath",
                new KeyValuePair<string, string[]>[]
                {
                    new KeyValuePair<string, string[]>("SAMLResponse", new string[] { "Some Data" })
                },
                null,
                null);

            Saml2Binding.Get(r).Should().BeOfType<Saml2PostBinding>();
        }

        [TestMethod]
        public void Saml2Binding_Get_ReturnsSaml2Artifact_ForArtifactInUrl()
        {
            var r = new HttpRequestData(
                "GET",
                new Uri("http://example.com/ModulePath/Acs?SAMLart=ABCD"));

            Saml2Binding.Get(r).Should().BeOfType<Saml2ArtifactBinding>();
        }

        [TestMethod]
        public void Saml2Binding_Get_ReturnsSamlArtifact_ForArtifactInPost()
        {
            var r = new HttpRequestData(
                "POST",
                new Uri("http://example.com/ModulePath"),
                "/ModulePath",
                new KeyValuePair<string, string[]>[]
                {
                    new KeyValuePair<string, string[]>("SAMLart", new string[] { "Some Data" })
                },
                null,
                null);

            Saml2Binding.Get(r).Should().BeOfType<Saml2ArtifactBinding>();
        }

        [TestMethod]
        public void Saml2Binding_Get_NullOnPlainGet()
        {
            var r = new HttpRequestData("GET", new Uri("http://example.com"));

            Saml2Binding.Get(r).Should().BeNull();
        }

        [TestMethod]
        public void Saml2Binding_Get_NullOnGetWithSamlResponseBody()
        {
            var r = new HttpRequestData(
                "GET",
                new Uri("http://example.com"),
                "/ModulePath",
                new KeyValuePair<string, string[]>[]
                {
                    new KeyValuePair<string, string[]>("SAMLResponse", new string[] { "Some Data" })
                },
                null,
                null);

            Saml2Binding.Get(r).Should().BeNull();
        }

        [TestMethod]
        public void Saml2Binding_Get_NullOnGetWithSamlartBody()
        {
            var r = new HttpRequestData(
                "GET",
                new Uri("http://example.com"),
                "/ModulePath",
                new KeyValuePair<string, string[]>[]
                {
                    new KeyValuePair<string, string[]>("SAMLart", new string[] { "Some Data" })
                },
                null,
                null);

            Saml2Binding.Get(r).Should().BeNull();
        }

        [TestMethod]
        public void Saml2Binding_Get_NullOnPostWithSamlartQuery()
        {
            var r = new HttpRequestData("POST", new Uri("http://example.com?Samlart=foo"));

            Saml2Binding.Get(r).Should().BeNull();
        }

        [TestMethod]
        public void Saml2Binding_Get_NullOnPlainPost()
        {
            var r = new HttpRequestData("POST", new Uri("http://example.com"));

            Saml2Binding.Get(r).Should().BeNull();
        }

        class ConcreteSaml2Binding : Saml2Binding
        {
            protected internal override bool CanUnbind(HttpRequestData request)
            {
                throw new NotImplementedException();
            }
        }

        [TestMethod]
        public void Saml2Binding_Bind_IsNotImplemented()
        {
            var message = new Saml2MessageImplementation();

            Action a = () => new ConcreteSaml2Binding().Bind(message);

            a.ShouldThrow<NotImplementedException>();
        }

        [TestMethod]
        public void Saml2Binding_Bind_ThrowsNotImplementedException()
        {
            new ConcreteSaml2Binding().Invoking(b => b.Bind(null))
                .ShouldThrow<NotImplementedException>();
        }

        [TestMethod]
        public void Saml2Binding_Unbind_IsNotImplemented()
        {
            Action a = () => new ConcreteSaml2Binding().Unbind(null, null);

            a.ShouldThrow<NotImplementedException>();
        }

        [TestMethod]
        public void Saml2Binding_UriToSaml2BindingType_Redirect()
        {
            Saml2Binding.UriToSaml2BindingType(Saml2Binding.HttpRedirectUri)
                .Should().Be(Saml2BindingType.HttpRedirect);
        }

        [TestMethod]
        public void Saml2Binding_UriToSaml2BindingType_Post()
        {
            Saml2Binding.UriToSaml2BindingType(Saml2Binding.HttpPostUri)
                .Should().Be(Saml2BindingType.HttpPost);
        }

        [TestMethod]
        public void Saml2Binding_UriToSaml2BindingType_Unknown()
        {
            Action a = () => Saml2Binding.UriToSaml2BindingType(new Uri("urn:SomeUnknownUri"));

            a.ShouldThrow<ArgumentException>().And.Message.Should().Be("Unknown Saml2 Binding Uri \"urn:SomeUnknownUri\".");
        }

        [TestMethod]
        public void Saml2Binding_UriToSaml2BindingType_Nullcheck()
        {
            Action a = () => Saml2Binding.UriToSaml2BindingType(null);

            a.ShouldThrow<ArgumentNullException>().And.ParamName.Should().Be("uri");
        }
    }
}
